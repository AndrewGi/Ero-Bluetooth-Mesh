import threading
from queue import Queue
from .mesh import *
from . import bearer, crypto, net, access, transport, beacon, replay, network, foundation, scheduler
from .models import model


class MessageContext:
	__slots__ = "src", "dst", "seq", "iv_index", "network_index", "app_index", "ttl", "local_device_key", \
				"remote_device_key", "big_access_mic"

	def __init__(self, src: UnicastAddress, dst: Address, ttl: TTL, seq: Seq, iv_index: Optional[IVIndex] = None
				 , network_index: Optional[NetKeyIndex] = None
				 , app_index: Optional[AppKeyIndex] = None, local_device_key: bool = False
				 , remote_device_key: bool = False
				 , big_access_mic: bool = False):
		self.src = src
		self.dst = dst
		self.seq = seq
		self.iv_index = iv_index
		self.network_index = network_index
		self.app_index = app_index
		self.ttl = ttl
		self.remote_device_key = remote_device_key
		self.local_device_key = local_device_key
		self.big_access_mic = big_access_mic

	@classmethod
	def from_net(cls, net_pdu: net.PDU) -> 'MessageContext':
		return cls(net_pdu.src, net_pdu.dst, net_pdu.ttl, net_pdu.seq)

	def device_nonce(self) -> crypto.DeviceNonce:
		assert self.local_device_key or self.remote_device_key
		return crypto.DeviceNonce(self.big_access_mic, self.seq, self.src, self.dst, self.iv_index)

	def application_nonce(self) -> crypto.ApplicationNonce:
		assert not (self.local_device_key or self.remote_device_key)
		return crypto.ApplicationNonce(self.big_access_mic, self.seq, self.src, self.dst, self.iv_index)


class Element:
	__slots__ = "element_id", "element_address", "models", "send_access"

	def __init__(self, element_id: foundation.ElementID, element_address: UnicastAddress,
				 models: List[model.Model]) -> None:
		self.element_id = element_id
		self.element_address = element_address
		self.models = models
		self.send_access: Optional[Callable[[access.AccessMessage], None]] = None

	def set_send_access(self, send_access: Callable[[access.AccessMessage], None]) -> None:
		self.send_access = send_access
		for element_model in self.models:
			element_model.send_access = self.send_access


class Elements:
	__slots__ = "elements", "send_access"

	def __init__(self, elements: List[Element]) -> None:
		self.send_access: Optional[Callable[[access.AccessMessage], None]] = None
		self.elements = elements

	def set_send_access(self, send_access: Callable[[access.AccessMessage], None]) -> None:
		self.send_access = send_access
		for element in self.elements:
			element.set_send_access(self.send_access)

	def primary(self) -> Element:
		return self.elements[0]

	def primary_address(self) -> UnicastAddress:
		return self.primary().element_address

	def __len__(self) -> int:
		return len(self.elements)

	def get_element_by_address(self, address: UnicastAddress) -> Element:
		l = len(self)
		primary_address = self.primary_address()
		if not primary_address < address < (primary_address + l):
			raise KeyError(f"{address} not in range of elements")
		return self.elements[address.value - primary_address.value]


class NetworkPDUSchedulerTask:
	def __init__(self, task: scheduler.Task) -> None:
		self.task = task


class TransportScheduler:

	def __init__(self, send_network_pdu: Callable[[net.PDU], None]) -> None:
		self.scheduler = scheduler.Scheduler()
		self.send_network_pdu: Callable[[net.PDU], None] = send_network_pdu


class Stack(Serializable):
	DEFAULT_TTL = TTL(0x10)
	DEFAULT_QUEUE_SIZE = 25

	def __init__(self, stack_bearer: bearer.Bearer, local_context: crypto.LocalContext, mesh_network: network.Network,
				 queue_max_sizes: Optional[int] = None):
		"""
		Initaized a Bluetooth Mesh stack for decode and encoding messages from network layer to access layer

		:param stack_bearer: The Bearer that handles sending and receiving network pdus and beacons
		:param local_context: The local context that has all the local node information (Addresses, etc)
		:param mesh_network: The mesh network context that has all the cryptographic information (keys, IV index, etc)
			Also we use the mesh network address space for finding device keys
		:param queue_max_sizes: If None, set to DEFAULT_QUEUE_SIZE. Set to 0 for no limit
		"""
		if not queue_max_sizes:
			queue_max_sizes = self.DEFAULT_QUEUE_SIZE
		self.stack_bearer = stack_bearer
		self.replay_cache: Optional[replay.ReplayCache] = None
		self.mesh_network: Optional[network.Network] = None
		self.set_network(mesh_network)
		self.local_context = local_context

		self.seq_lock = threading.Lock()

		self.incoming_network_pdu_bytes_queue: Queue[bytes] = Queue(maxsize=queue_max_sizes)
		self.incoming_access_message_queue: Queue[access.AccessMessage] = Queue(maxsize=queue_max_sizes)
		self.incoming_beacons_queue: Queue[beacon.Beacon] = Queue(maxsize=queue_max_sizes)
		self.outgoing_access_message_queue: Queue[Tuple[access.AccessMessage, foundation.ModelPublication]] = Queue(
			maxsize=queue_max_sizes)
		self.outgoing_network_pdu_bytes_queue: Queue[bytes] = Queue(maxsize=queue_max_sizes)

		self.outgoing_network_pdu_bytes_thread = threading.Thread(target=self.send_network_pdu_bytes_worker)
		self.outgoing_network_pdu_bytes_thread.start()

		self.reassemblers = transport.Reassemblers(self.DEFAULT_TTL)
		self.segmented_messages = transport.SegmentedMessages()

	def set_network(self, new_network: network.Network) -> None:
		self.mesh_network = new_network
		self.replay_cache = replay.ReplayCache(self.iv_index())

	def iv_index(self) -> IVIndex:
		return self.mesh_network.global_context.iv_index

	def set_bearer(self, stack_bearer: bearer.Bearer) -> None:
		"""
		Sets the stack's bearer. This overwrites the bearer's 'recv_network_pdu' and
		'recv_beacon' function. It's use the bearer's 'send_network_pdu' and 'send_beacon' as well.
		:param stack_bearer: the new stack bearer !!GETS MODIFIED!!
		"""
		self.stack_bearer = stack_bearer
		self.stack_bearer.recv_network_pdu = self.recv_network_pdu_bytes
		self.stack_bearer.recv_beacon = self.recv_beacon

	def to_dict(self) -> Dict[str, Any]:
		return {
			"local_context": self.local_context.to_dict(),
			"replay_cache": self.replay_cache.to_dict()
		}

	@staticmethod
	def _net_to_lower_transport(pdu: net.PDU) -> transport.LowerPDU:
		return transport.make_lower_pdu(pdu.transport_pdu, pdu.ctl)

	def _queue_incoming_access_message(self, msg: access.AccessMessage) -> None:
		self.incoming_access_message_queue.put(msg)

	def _handle_unencrypted_access(self, pdu: transport.UpperAccessPDU, context: MessageContext) -> None:
		payload = access.AccessPayload.from_bytes(pdu.payload)
		msg = access.AccessMessage(context.src, context.dst, context.ttl, payload.opcode, payload.parameters,
								   context.app_index, context.network_index, pdu.big_mic, context.local_device_key,
								   context.remote_device_key)
		self._queue_incoming_access_message(msg)

	def _handle_encrypted_access(self, pdu: transport.UpperEncryptedAccessPDU, context: MessageContext) -> None:
		if not pdu.akf():
			# try to decrypt with local device key
			local_device_sm = self.local_context.device_sm
			device_nonce = context.device_nonce()
			try:
				upper_access = pdu.decrypt(device_nonce, local_device_sm)
			except crypto.InvalidMIC:
				# didn't match
				pass
			else:
				context.local_device_key = True
				self._handle_unencrypted_access(upper_access, context)
				return

			# didn't match local device key, lets try the src address
			try:
				remote_device_sm = self.mesh_network.get_device_key(context.src)
			except KeyError:
				# No devices exists under given primary src address
				return
			else:
				if not remote_device_sm:
					raise PermissionError(f"missing device security materials for {context.src}")
				try:
					upper_access = pdu.decrypt(device_nonce, remote_device_sm)
				except crypto.InvalidMIC:
					# didn't match
					pass
				else:
					context.remote_device_key = True
					self._handle_unencrypted_access(upper_access, context)
					return
			# otherwise we don't know the device key so we ignore it
			return

		app_nonce = context.application_nonce()
		for index, sm in self.mesh_network.global_context.get_aid_rx_keys(pdu.aid):
			try:
				access_payload = pdu.decrypt(app_nonce, sm)
				context.app_index = index
				self._handle_unencrypted_access(access_payload, context)
				return
			except crypto.InvalidMIC:
				pass

	# unable to decrypt app payload

	def _handle_lower_transport_pdu(self, pdu: transport.LowerPDU, context: MessageContext):
		if isinstance(pdu, transport.UnsegmentedControlLowerPDU):
			self._handle_control(pdu)
			return
		if isinstance(pdu, transport.UnsegmentedAccessLowerPDU):
			self._handle_encrypted_access(pdu.upper_pdu, context)
			return
		assert isinstance(pdu, transport.LowerSegmentedPDU)
		pdu = cast(transport.LowerSegmentedPDU, pdu)
		out: Optional[transport.UpperEncryptedAccessPDU] = self.reassemblers.handle(context.src, pdu)
		if out:
			self._handle_encrypted_access(out, context)

	def _handle_control(self, pdu: transport.UnsegmentedControlLowerPDU) -> None:
		"""
		Handle heartbeat and acks
		:param pdu: incoming control PDU to handle
		:return:
		"""

	def _handle_network_pdu(self, pdu: net.PDU, context: MessageContext) -> None:
		if not self.replay_cache.verify_net(pdu):
			# we already saw this PDU
			# discard
			return
		self._handle_lower_transport_pdu(self._net_to_lower_transport(pdu), context)

	def _handle_network_pdu_bytes(self, pdu: bytes) -> None:
		ivi, nid = net.PDU.ivi_nid(pdu)
		iv_index = self.mesh_network.global_context.get_iv_index(ivi)
		for net_index, sm in self.mesh_network.global_context.get_nid_rx_keys(nid):
			try:
				net_pdu = net.PDU.from_bytes(pdu, sm, iv_index)
				context = MessageContext.from_net(net_pdu)
				context.iv_index = iv_index
				context.network_index = net_index
				self._handle_network_pdu(net_pdu, context)
			except crypto.InvalidMIC:
				# Unable to decode network pdu
				pass

	def recv_network_pdu_bytes(self, pdu: bytes) -> None:
		"""
		Queue's encrypted network pdu to be processed by the stack
		:param pdu: encrypted network pdu as bytes
		"""
		self.incoming_network_pdu_bytes_queue.put(pdu)

	def recv_beacon(self, incoming_beacon: beacon.Beacon):
		self.incoming_beacons_queue.put(incoming_beacon)

	@classmethod
	def default_ttl(cls) -> TTL:
		return cls.DEFAULT_TTL

	def app_nonce(self, msg: access.AccessMessage) -> crypto.ApplicationNonce:
		assert not msg.device_key() and msg.appkey_index is not None
		return crypto.ApplicationNonce(msg.big_mic, self.local_context.seq, msg.src, msg.dst,
									   self.mesh_network.global_context.iv_index)

	def device_nonce(self, msg: access.AccessMessage) -> crypto.DeviceNonce:
		assert msg.device_key() and msg.appkey_index is None
		return crypto.DeviceNonce(msg.big_mic, self.local_context.seq, msg.src, msg.dst,
								  self.mesh_network.global_context.iv_index)

	def encrypt_access(self, msg: access.AccessMessage) -> transport.UpperEncryptedAccessPDU:
		sm = self.local_context.device_sm if msg.device_key() else self.mesh_network.global_context.get_app(
			msg.appkey_index)
		nonce = self.device_nonce(msg) if msg.device_key() else self.app_nonce(msg)
		payload = msg.payload().to_bytes()
		return transport.UpperAccessPDU(payload, msg.big_mic).encrypt(nonce, sm)

	def first_send_segmented_message(self, msgs: transport.SegmentedMessage) -> None:
		self.segmented_messages.add(msgs)

	def resend_segmented_message(self, context: transport.SegmentedContext) -> None:
		msgs = context.msg
		if msgs.retransmit <= 0:
			raise ValueError("segments out of retransmits")
		lowers: List[transport.LowerSegmentedPDU] = list(msgs.get_unacked())

		def lower_to_pdu():
			seq = self.seq_allocate(len(lowers))
			for lower in lowers:
				yield net.PDU(self.iv_index().ivi(), msgs.net_sm.nid, False, msgs.ttl, seq, msgs.src, msgs.dst,
							  lower.to_bytes())
				seq += 1

		for net_pdu in lower_to_pdu():
			self.queue_outgoing_network_pdu(net_pdu, msgs.net_sm.encryption_key)

	def seq_allocate(self, amount: int) -> Seq:
		with self.seq_lock:
			return self.local_context.seq_allocate(amount)

	def seq_and_inc(self) -> Seq:
		with self.seq_lock:
			return self.local_context.seq_inc()

	def lower_transport_to_network_pdu(self, lower_pdu: transport.LowerPDU, src: UnicastAddress, dst: Address,
									   seq: Seq, nid: NID, ttl: TTL) -> net.PDU:
		return net.PDU(self.iv_index().ivi(), nid, False, ttl, seq, src, dst,
					   lower_pdu.to_bytes())

	def queue_access_message(self, msg: access.AccessMessage) -> None:
		self.outgoing_access_message_queue.put(msg)

	def running(self) -> bool:
		return True

	def send_access_message_worker(self) -> None:
		while self.running():
			next_item: Tuple[
				access.AccessMessage, foundation.ModelPublication] = self.outgoing_access_message_queue.get()
			if next_item is None:
				break
			self.send_access_message(next_item[0], next_item[1])
			self.outgoing_access_message_queue.task_done()

	def send_access_message(self, msg: access.AccessMessage, publication: foundation.ModelPublication):
		net_sm = cast(crypto.NetworkSecurityMaterial,
					  self.mesh_network.global_context.get_net(msg.netkey_index).tx_sm())
		encrypted_access = self.encrypt_access(msg)
		ttl = publication.publish_ttl if msg.ttl == TTL.DEFAULT_TTL else msg.ttl
		if encrypted_access.should_segment() or msg.force_segment:
			# Use Segmentation to send the message.
			segmented_generator = encrypted_access.segmented(self.seq_allocate(encrypted_access.seg_n()))
			segmented_msg = transport.SegmentedMessage(list(segmented_generator), msg.src, msg.dst, net_sm, ttl)
			self.first_send_segmented_message(segmented_msg)
		else:
			# send unsegmeneted
			unsegmented = encrypted_access.access_unsegmented()
			net_pdu = self.lower_transport_to_network_pdu(unsegmented, msg.src, msg.dst, self.seq_and_inc(), net_sm.nid,
														  ttl)
			self.queue_outgoing_network_pdu(net_pdu, net_sm.encryption_key)

	def send_network_pdu_bytes_worker(self) -> None:
		while True:
			next_item = self.outgoing_network_pdu_bytes_queue.get()
			if next_item is None:
				break
			self.send_network_pdu_bytes(*next_item)
			self.outgoing_network_pdu_bytes_queue.task_done()

	def send_network_pdu_bytes(self, pdu: bytes, transmit_parameters: TransmitParameters):
		self.stack_bearer.send_network_pdu(pdu, transmit_parameters)

	def queue_outgoing_network_pdu(self, network_pdu: net.PDU, key: crypto.EncryptionKey):
		self.outgoing_network_pdu_bytes_queue.put(crypto.data_and_mic_bytes(*network_pdu.encrypt(key, self.iv_index())),
												  self.local_context.transmit_parameters)

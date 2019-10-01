from queue import Queue
from .mesh import *
from . import bearer, crypto, net, access, transport, beacon, replay, model, network


class MessageContext:
	__slots__ = "src", "dst", "seq", "iv_index", "network_index", "app_index", "ttl", "device_key", "big_access_mic"

	def __init__(self, src: UnicastAddress, dst: Address, ttl: TTL, seq: Seq, iv_index: Optional[IVIndex] = None,
				 network_index: Optional[NetKeyIndex] = None
				 , app_index: Optional[AppKeyIndex] = None, device_key: Optional[bool] = False,
				 big_access_mic: Optional[bool] = False):
		self.src = src
		self.dst = dst
		self.seq = seq
		self.iv_index = iv_index
		self.network_index = network_index
		self.app_index = app_index
		self.ttl = ttl
		self.device_key = device_key
		self.big_access_mic = big_access_mic

	@classmethod
	def from_net(cls, net_pdu: net.PDU) -> 'MessageContext':
		return cls(net_pdu.src, net_pdu.dst, net_pdu.ttl, net_pdu.seq)

	def device_nonce(self) -> crypto.DeviceNonce:
		assert self.device_key
		return crypto.DeviceNonce(self.big_access_mic, self.seq, self.src, self.dst, self.iv_index)

	def application_nonce(self) -> crypto.ApplicationNonce:
		assert not self.device_key
		return crypto.ApplicationNonce(self.big_access_mic, self.seq, self.src, self.dst, self.iv_index)


class Stack:
	DEFAULT_TTL = TTL(0x10)
	DEFAULT_QUEUE_SIZE = 25

	def __init__(self, stack_bearer: bearer.Bearer, mesh_network: network.Network, queue_max_sizes: Optional[int] = None):
		"""
		Initaized a Bluetooth Mesh stack for decode and encoding messages from network layer to access layer

		:param stack_bearer: The Bearer that handles sending and receiving network pdus and beacons
		:param global_context: Holds global indexed key list and iv_index
		:param local_context: Holds device key and seq number
		:param queue_max_sizes: If None, set to DEFAULT_QUEUE_SIZE. Set to 0 for no limit
		"""
		if not queue_max_sizes:
			queue_max_sizes = self.DEFAULT_QUEUE_SIZE
		self.stack_bearer = stack_bearer
		self.mesh_network = mesh_network

		self.incoming_network_pdu_bytes_queue: Queue[bytes] = Queue(maxsize=queue_max_sizes)
		self.incoming_access_message_queue: Queue[access.AccessMessage] = Queue(maxsize=queue_max_sizes)
		self.incoming_beacons_queue: Queue[beacon.Beacon] = Queue(maxsize=queue_max_sizes)

		self.outgoing_access_message_queue: Queue[access.AccessMessage] = Queue(maxsize=queue_max_sizes)

		self.replay_cache = replay.ReplayCache(self.iv_index())
		self.reassemblers = transport.Reassemblers()

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

	@staticmethod
	def _net_to_lower_transport(pdu: net.PDU) -> transport.LowerPDU:
		return transport.make_lower_pdu(pdu.transport_pdu, pdu.ctl)

	def _queue_incoming_access_message(self, msg: access.AccessMessage) -> None:
		self.incoming_access_message_queue.put(msg)

	def _handle_unencrypted_access(self, pdu: transport.UpperAccessPDU, context: MessageContext) -> None:
		payload = access.AccessPayload.from_bytes(pdu.payload)
		msg = access.AccessMessage(context.src, context.dst, context.ttl, payload.opcode, payload.parameters,
								   context.app_index, context.network_index, pdu.big_mic, context.device_key)
		self._queue_incoming_access_message(msg)

	def _handle_encrypted_access(self, pdu: transport.UpperEncryptedAccessPDU, context: MessageContext) -> None:
		if not pdu.akf():
			context.device_key = True
			device_sm = crypto.DeviceSecurityMaterial(cast(network.RemoteDevice, self.mesh_network.addresses.unicasts[context.src]).device_key)
			if not device_sm:
				raise PermissionError(f"missing device security materials for {context.src}")
			upper_access = pdu.decrypt(context.device_nonce(), device_sm)
			self._handle_unencrypted_access(upper_access, context)
			return

		context.device_key = False
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
		pdu = cast(transport.LowerSegmentedPDU, pdu)
		out: Optional[transport.UpperEncryptedAccessPDU] = self.reassemblers.handle(context.src, pdu)
		if out:
			self._handle_encrypted_access(out, context)

	def _handle_control(self, pdu: transport.UnsegmentedControlLowerPDU):
		pass

	def _handle_network_pdu(self, pdu: net.PDU, context: MessageContext) -> None:
		if not self.replay_cache.verify_net(pdu):
			# we already saw this PDU
			# discard
			return
		context = MessageContext.from_net(pdu)
		self._handle_lower_transport_pdu(self._net_to_lower_transport(pdu), context)

	def _handle_network_pdu_bytes(self, pdu: bytes) -> None:
		ivi, nid = net.PDU.ivi_nid(pdu)
		iv_index = self.global_context.get_iv_index(ivi)
		for net_index, sm in self.global_context.get_nid_rx_keys(nid):
			try:
				net_pdu = net.PDU.from_bytes(pdu, sm, iv_index)
				context = MessageContext.from_net(net_pdu)
				context.network_index = net_index
				self._handle_network_pdu(net_pdu, context)
			except crypto.InvalidMIC:
				pass

	# Unable to decode network pdu

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
		assert not msg.device_key and msg.appkey_index is not None
		return crypto.ApplicationNonce(msg.big_mic, self.local_context.seq, msg.src, msg.dst,
									   self.global_context.iv_index)

	def device_nonce(self, msg: access.AccessMessage) -> crypto.DeviceNonce:
		assert msg.device_key and msg.appkey_index is None
		return crypto.DeviceNonce(msg.big_mic, self.local_context.seq, msg.src, msg.dst, self.global_context.iv_index)

	def encrypt_access(self, msg: access.AccessMessage) -> transport.UpperEncryptedAccessPDU:
		sm = self.local_context.device_sm if msg.device_key else self.global_context.get_app(msg.appkey_index)
		nonce = self.device_nonce(msg) if msg.device_key else self.app_nonce(msg)
		payload = msg.payload().to_bytes()
		return transport.UpperAccessPDU(payload, msg.big_mic).encrypt(nonce, sm)

	def _access_lower_pdus(self, msg: access.AccessMessage, encrypted: transport.UpperEncryptedAccessPDU) -> Generator[
		Union[transport.SegmentedAccessLowerPDU, transport.UnsegmentedAccessLowerPDU], None, None]:
		if msg.force_segment or encrypted.should_segment():
			for seg in encrypted.segmented(self.local_context.seq):
				self.local_context.seq_inc()
				yield seg
		else:
			self.local_context.seq_inc()
			yield encrypted.unsegmented()

	def seq(self) -> Seq:
		return self.local_context.seq()

	def access_network_pdus(self, msg: access.AccessMessage, net_sm: crypto.NetworkSecurityMaterial) -> Generator[
		net.PDU, None, None]:
		encrypted = self.encrypt_access(msg)
		for lower_pdu in self._access_lower_pdus(msg, encrypted):
			yield net.PDU(self.iv_index().ivi(), net_sm.nid, False, msg.ttl, self.seq(), msg.src, msg.dst,
						  lower_pdu.to_bytes())

	def send_access_message(self, msg: access.AccessMessage):
		net_sm = cast(crypto.NetworkSecurityMaterial, self.global_context.get_net(msg.netkey_index).tx_sm())
		encrypted_access = self.encrypt_access()

		pdus = [pdu for pdu in self.access_network_pdus(msg, net_sm)]  # we update SEQ here so we want to do it fast
		for pdu in pdus:
			self.send_network_pdu(pdu, net_sm.encryption_key)

	def send_network_pdu_bytes(self, pdu: bytes):
		self.stack_bearer.send_network_pdu(pdu)

	def send_network_pdu(self, network_pdu: net.PDU, key: crypto.EncryptionKey):
		self.send_network_pdu_bytes(crypto.data_and_mic_bytes(*network_pdu.encrypt(key, self.iv_index())))

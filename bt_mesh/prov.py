import datetime
import enum
import math
import queue
import random
import struct
import threading
from typing import Union, Optional, List, Generator, Iterator, NewType
from uuid import UUID

from . import crypto, beacon, mesh, pb_generic, bearer


class PDUType(enum.IntEnum):
	Invite = 0
	Capabilities = 1
	Start = 2
	PublicKey = 3
	InputComplete = 4
	Confirmation = 5
	Random = 6
	Data = 7
	Complete = 8
	Failed = 9


pdu_classes = dict()  # type: Dict[PDUType, Any]


class PDU:
	__slots__ = "pdu_type",

	def __init__(self, pdu_type: PDUType):
		if pdu_type > 0x1F:
			raise ValueError(f"pdu type too high {pdu_type}")
		self.pdu_type = pdu_type

	def parameters_to_bytes(self) -> bytes:
		raise NotImplementedError()

	@classmethod
	def parameters_from_bytes(cls, b: bytes):
		raise NotImplementedError()

	def to_bytes(self):
		return bytes([self.pdu_type]) + self.parameters_to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'PDU':
		pdu_type = PDUType(b[0] >> 2)
		return pdu_classes[pdu_type].parameters_from_bytes(b[1:])


class Invite(PDU):
	__slots__ = "attention_duration",

	def __init__(self, attention_duration: int):
		super().__init__(PDUType.Invite)
		self.attention_duration = attention_duration

	def parameters_to_bytes(self) -> bytes:
		return bytes([self.attention_duration])

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'Invite':
		return cls(b[0])


class Algorithms(enum.IntEnum):
	FIPSP256 = 0

	def check_enabled(self, algorithm: 'Algorithms'):
		return (1 << algorithm) & self == 1


class OOBSize(enum.IntEnum):
	pass


class OutputOOBAction(enum.IntEnum):
	NoAction = 0x00
	Blink = 0x01
	Beep = 0x02
	Vibrate = 0x04
	OutputNumeric = 0x08
	OutputAlphanumeric = 0x0F


class InputOOBAction(enum.IntEnum):
	NoAction = 0x00
	Push = 0x01
	Twist = 0x02
	InputNumber = 0x04
	InputAlphanumeric = 0x08


class Capabilities(PDU):
	STRUCT = struct.Struct("!BHBBBHBH")
	__slots__ = "number_of_elements", "algorithms", "public_key_type", "static_oob_type", "output_oob_size", "output_oob_action", "input_oob_size", "input_oob_action"

	def __init__(self, number_of_elements: int, algorithms: Algorithms, public_key_type: bool,
				 static_oob_type: bool, output_oob_size: OOBSize, output_oob_action: OutputOOBAction,
				 input_oob_size: OOBSize, input_oob_action: InputOOBAction):
		super().__init__(PDUType.Capabilities)
		self.number_of_elements = number_of_elements
		self.algorithms = algorithms
		self.public_key_type = public_key_type
		self.static_oob_type = static_oob_type
		self.output_oob_size = output_oob_size
		self.output_oob_action = output_oob_action
		self.input_oob_size = input_oob_size
		self.input_oob_action = input_oob_action

	def parameters_to_bytes(self) -> bytes:
		return self.STRUCT.pack(self.number_of_elements, self.algorithms, self.public_key_type, self.static_oob_type,
								self.output_oob_size, self.output_oob_action, self.input_oob_size,
								self.input_oob_action)

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'Capabilities':
		return cls(*cls.STRUCT.unpack(b))


class PublicKey(enum.IntEnum):
	NoOOB = 0
	YesOOB = 1


class AuthenticationMethod(enum.IntEnum):
	NoOOB = 0
	StaticOOB = 1
	OutputOOB = 2
	InputOOB = 3


AuthenticationMethod = Union[OutputOOBAction, InputOOBAction]


class Start(PDU):
	STRUCT = struct.Struct("!BBBBB")
	__slots__ = "algorithm", "public_key", "authentication_method", "authentication_action", "authentication_size"

	def __init__(self, algorithm: Algorithms, public_key: PublicKey, authentication_method: AuthenticationMethod,
				 authentication_action: AuthenticationMethod, authentication_size: OOBSize):
		super().__init__(PDUType.Start)
		self.algorithm = algorithm
		self.public_key = public_key
		self.authentication_method = authentication_method
		self.authentication_action = authentication_action
		self.authentication_size = authentication_size

	def parameters_to_bytes(self) -> bytes:
		return self.STRUCT.pack(self.algorithm, self.public_key, self.authentication_method, self.authentication_action,
								self.authentication_size)

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'Start':
		return cls(*cls.STRUCT.unpack(b))


class PublicKey(PDU):
	__slots__ = "x", "y"

	def __init__(self, x: crypto.PublicKeyXY, y: crypto.PublicKeyXY):
		super().__init__(PDUType.PublicKey)
		self.x = x
		self.y = y

	def parameters_to_bytes(self) -> bytes:
		return struct.pack("32s32s", self.x, self.y)

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'PublicKey':
		return cls(*struct.unpack("32s32s", b))


class InputComplete(PDU):
	def __init__(self):
		super().__init__(PDUType.InputComplete)

	def parameters_to_bytes(self) -> bytes:
		return bytes()

	def parameters_from_bytes(cls, b: bytes):
		if len(b) != 0:
			raise ValueError("input complete not empty")
		return cls()


class Confirmation(PDU):
	LEN = 16
	__slots__ = "data"

	def __init__(self, data: bytes):
		super().__init__(PDUType.Confirmation)
		self.data = data

	def bearer_to_bytes(self) -> bytes:
		return self.data

	@classmethod
	def bearer_from_bytes(cls, b: bytes) -> 'Confirmation':
		return cls(b)


class Random(PDU):
	LEN = 16
	__slots__ = "random_data",

	def __init__(self, random_data: bytes):
		super().__init__(PDUType.Random)
		if len(random_data) != self.LEN:
			raise ValueError("random data wrong length")
		self.random_data = random_data

	def parameters_to_bytes(self) -> bytes:
		return self.random_data

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'Random':
		return cls(b)


class Data(PDU):
	MIC_LEN = 8
	DATA_LEN = 25
	__slots__ = "encrypted_data", "mic"

	def __init__(self, data: bytes, mic: mesh.MIC):
		if len(data) != self.DATA_LEN:
			raise ValueError("invalid data length")
		if mic.mic_len() != self.MIC_LEN * 8:
			raise ValueError("invalid mic length")
		self.encrypted_data = data
		self.mic = mic

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'Data':
		return cls(b[:cls.DATA_LEN], mesh.MIC(b[cls.DATA_LEN:]))

	def parameters_to_bytes(self) -> bytes:
		return self.encrypted_data + self.mic.bytes_be


class ErrorCode(enum.IntEnum):
	Prohibited = 0
	InvalidPDU = 1
	InvalidFormat = 2
	UnexpectedPDU = 3
	ConfirmationFailed = 4
	OutOfResources = 5
	DecryptionFailed = 6
	UnexpectedError = 7
	CannotAssignAddresses = 8


class Failed(PDU):
	__slots__ = "error_code",

	def __init__(self, error_code: ErrorCode):
		super().__init__(PDUType.Failed)
		self.error_code = error_code

	def parameters_to_bytes(self) -> bytes:
		return self.error_code.to_bytes(1, byteorder="big")

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'Failed':
		return cls(ErrorCode(b[0]))


pdu_classes[PDUType.Invite] = Invite
pdu_classes[PDUType.Capabilities] = Capabilities
pdu_classes[PDUType.Start] = Start
pdu_classes[PDUType.PublicKey] = PublicKey
pdu_classes[PDUType.InputComplete] = InputComplete
pdu_classes[PDUType.Confirmation] = Confirmation
pdu_classes[PDUType.Random] = Random
pdu_classes[PDUType.Data] = Data
pdu_classes[PDUType.Confirmation] = Confirmation
pdu_classes[PDUType.Failed] = Failed


def segment_pdu(pdu: PDU, max_mtu: int) -> Generator[pb_generic.GenericProvisioningPDU, None, None]:
	pdu_bytes = pdu.to_bytes()
	start_data_size = max_mtu - pb_generic.TransactionStartPDU.control_pdu_size()
	if start_data_size < 1:
		raise ValueError("MTU too small")

	max_continue_data_size = max_mtu - pb_generic.TransactionContinuationPDU.control_pdu_size()
	seg_n = math.ceil((len(pdu_bytes) - start_data_size) / max_continue_data_size)
	start_data_size = len(pdu_bytes) if start_data_size > len(pdu_bytes) else start_data_size
	yield pb_generic.TransactionStartPDU(seg_n, len(pdu_bytes), data=pdu_bytes[:start_data_size])
	for seg_i in range(seg_n):
		start_i = start_data_size + seg_i * max_continue_data_size
		end_i = start_i + max_continue_data_size
		if end_i > len(pdu_bytes):
			end_i = len(pdu_bytes)
		yield pb_generic.TransactionContinuationPDU(seg_i, pdu_bytes[start_i:end_i])


class Reassembler:
	def __init__(self, total_length: int, seg_n: int, fcs: int, mtu: int, transaction_number: int):
		self.total_length = total_length
		self.fcs = fcs
		self.mtu = mtu
		self.start_seg_len = mtu - pb_generic.TransactionStartPDU.control_pdu_size()
		self.continue_seg_len = mtu - pb_generic.TransactionContinuationPDU.control_pdu_size()
		self.seg_n = seg_n
		self.seg_mask = (2 ** self.seg_n) - 1
		self.segs_needed = self.seg_mask
		self.transaction_number = transaction_number
		self.data = bytearray(total_length)

	@classmethod
	def from_start_pdu(cls, start_pdu: pb_generic.TransactionStartPDU, mtu: int):
		assembler = cls(start_pdu.length, start_pdu.seg_n, start_pdu.fcs, mtu, start_pdu.transaction_number)
		assembler.insert_pdu(start_pdu)
		return assembler

	def seg_pos(self, seg_i: int) -> int:
		pos = 0
		if seg_i <= 0:
			return pos
		pos += self.start_seg_len
		if seg_i == 1:
			return pos
		for _ in range(seg_i - 1):
			pos += self.continue_seg_len
		return pos

	def insert_segment(self, seg_i: int, data: bytes):
		if seg_i != self.seg_n:
			if seg_i == 0 and len(data) != self.start_seg_len:
				raise ValueError("transaction start pdu too small")
			if seg_i > 0 and len(data) != self.continue_seg_len:
				raise ValueError("transaction continue pdu too small")
		pos = self.seg_pos(seg_i)
		if pos + len(data) > self.total_length:
			raise ValueError("data out of bounds")
		for i in range(len(data)):
			self.data[i + pos] = data[i]
		self.segs_needed = self.segs_needed & (~(1 << seg_i) & self.seg_mask)

	def payload(self) -> bytes:
		if not self.is_done():
			raise ValueError("message not assembled yet")
		return self.data

	def ack(self) -> pb_generic.TransactionAckPDU:
		if not self.is_done():
			raise ValueError("message not done. cant ack")
		return pb_generic.TransactionAckPDU(self.transaction_number)

	def insert_pdu(self, pdu: Union[pb_generic.TransactionStartPDU, pb_generic.TransactionContinuationPDU]):
		if pdu.transaction_number != self.transaction_number:
			# wrong transaction number
			return
		if pdu.gpcf() == pb_generic.GPCF.TRANSACTION_START:
			self.insert_segment(0, pdu.payload())
		else:
			self.insert_segment(pdu.seg_n, pdu.payload())

	def is_done(self) -> bool:
		print(f"segs needed : {bin(self.segs_needed)}")
		return self.segs_needed == 0

TransactionNumber = NewType("TransactionNumber", int)
class ProvisionerBearer:
	START_TRANSACTION_NUMBER = TransactionNumber(0x00)
	END_TRANSACTION_NUMBER = TransactionNumber(0x7F)
	def __init__(self):
		self.message_ack_cv = threading.Condition()
		self.transaction_assembler = None # type: Reassembler
		self.transaction_number = self.START_TRANSACTION_NUMBER

	def open(self):
		raise NotImplementedError()

	def mtu(self) -> int:
		raise NotImplementedError()

	def wait_for_ack(self, timeout: Optional[float] = None) -> bool:
		with self.message_ack_cv:
			return self.message_ack_cv.wait(timeout)

	def message_ackked(self):
		print("MESSAGE ACKED")
		self.transaction_number = TransactionNumber(self.transaction_number + 1)
		if self.transaction_number > self.END_TRANSACTION_NUMBER:
			self.transaction_number = self.END_TRANSACTION_NUMBER
		with self.message_ack_cv:
			self.message_ack_cv.notify_all()

	def close(self, reason: pb_generic.LinkCloseReason):
		raise NotImplementedError()

	def send_prov_pdu(self, pdu: PDU):
		self.send_generic_prov_pdus(segment_pdu(pdu, self.mtu()))

	def recv_prov_pdu(self, pdu: PDU):
		pass

	def send_generic_prov_pdus(self, pdus: Iterator[pb_generic.GenericProvisioningPDU]):
		raise NotImplementedError()

	def handle_transaction_start(self, start_pdu: pb_generic.TransactionStartPDU):
		print(f"START {start_pdu.transaction_number}")
		if self.transaction_assembler and self.transaction_assembler.transaction_number == start_pdu.transaction_number:
			return # we already started this transaction
		self.transaction_assembler = Reassembler.from_start_pdu(start_pdu, self.mtu())


	def recv_generic_prov_pdu(self, incoming_pdu: pb_generic.GenericProvisioningPDU):
		print(incoming_pdu)
		if incoming_pdu.gpcf() == pb_generic.GPCF.TRANSACTION_ACK:
			if incoming_pdu.transaction_number == self.transaction_number:
				self.message_ackked()
				return

		if incoming_pdu.gpcf() == pb_generic.GPCF.TRANSACTION_START:
			self.handle_transaction_start(incoming_pdu)
		elif incoming_pdu.gpcf() == pb_generic.GPCF.TRANSACTION_CONTINUE:
			if not self.transaction_assembler:
				# no reassembler so probably stale continue
				return
			self.transaction_assembler.insert_pdu(incoming_pdu)
		if self.transaction_assembler and self.transaction_assembler.is_done():
			pdu_data = self.transaction_assembler.payload()
			self.send_generic_prov_pdus([self.transaction_assembler.ack()])
			self.recv_prov_pdu(PDU.from_bytes(pdu_data))
			self.transaction_assembler = None

	def __del__(self):
		self.close(pb_generic.LinkCloseReason.Fail)


# the numbers don't matter
class ProvisioningEvent(enum.IntEnum):
	Open = 0
	Invite = 1
	Connected = 2
	Disconnected = 3
	Capabilities = 4
	Start = 5


class UnprovisionedDevice:
	# __slots__ = "last_seen", "device_uuid", "last_beacon", "pb_bearer", "invited", "worker_queue", "worker"
	def __init__(self, beacon: beacon.UnprovisionedBeacon):
		self.last_seen = beacon.last_seen
		self.device_uuid = beacon.dev_uuid
		self.last_beacon = beacon
		self.pb_bearer = None  # type: ProvisionerBearer
		self.invited = False
		self.provision_on_connect = False
		self.worker_queue = queue.Queue()
		self.worker = threading.Thread(target=self.worker_func)
		self.worker.start()
		self.algorithm = None # type: Algorithms
		self.auth_method = AuthenticationMethod.NoOOB
		self.capabilities = None  # type: Capabilities

	def _openned_event(self):
		self.worker_queue.put(ProvisioningEvent.Connected)

	def open(self):
		self.pb_bearer.open()

	def start(self):
		self.worker_queue.put(ProvisioningEvent.Start)

	def handle_event(self, provisioning_event: ProvisioningEvent):
		if provisioning_event == ProvisioningEvent.Invite:
			print(f"inviting {self.device_uuid}")
			self.do_invite()
		elif provisioning_event == ProvisioningEvent.Open:
			print(f"openning {self.device_uuid}")
			self.open()
		elif provisioning_event == ProvisioningEvent.Connected:
			print(f"{self.device_uuid} connected!")
			if self.provision_on_connect:
				self.invite()
		elif provisioning_event == ProvisioningEvent.Capabilities:
			print(f"{self.device_uuid} capabilities received!")
			if self.provision_on_connect:
				self.start()
		elif provisioning_event == ProvisioningEvent.Start:
			print(f"{self.device_uuid} starting provision process...")
			self.do_start()

	def do_invite(self):
		self.pb_bearer.send_prov_pdu(Invite(5))

	def do_start(self):
		if not self.capabilities:
			raise ValueError("unknown capabilities")
		# TODO: support more algorithms when they become available
		if not self.capabilities.algorithms.check_enabled(Algorithms.FIPSP256):
			raise AttributeError("no supported encryption algorithms")
		self.algorithm = Algorithms.FIPSP256
		if self.auth_method == AuthenticationMethod.InputOOB:
			if self.capabilities.input_oob_action == InputOOBAction.NoAction:
				raise ValueError("requested input oob when device doesn't support it")
		if self.auth_method == AuthenticationMethod.OutputOOB:
			if self.capabilities.output_oob_action == OutputOOBAction.NoAction:
				raise ValueError("requested output oob when device doesn't support it")
		if self.auth_method == AuthenticationMethod.StaticOOB:
			if not self.capabilities.static_oob_type:
				raise ValueError("requested static oob when device doesn't support it")
		self.pb_bearer.send_prov_pdu(Start())

	def worker_func(self):
		while True:
			item = self.worker_queue.get()
			if not item:
				break
			self.handle_event(item)
			self.worker_queue.task_done()

	def recv_pdu(self, pdu: PDU):
		self.last_seen = datetime.datetime.now()
		pass

	def set_bearer(self, pb_bearer: ProvisionerBearer):
		self.pb_bearer = pb_bearer
		pb_bearer.recv_prov_pdu = self.recv_pdu

	def update_beacon(self, new_beacon: beacon.UnprovisionedBeacon):
		if new_beacon.dev_uuid != self.device_uuid:
			raise ValueError("new beacon dev_uuid does not match set uuid")
		if new_beacon.last_seen < self.last_seen:
			raise ValueError("incoming beacon is older than last_seen")  # beacon is old
		self.last_seen = new_beacon.last_seen
		self.last_beacon = new_beacon
		self.device_uuid = new_beacon.dev_uuid

	def invite(self):
		self.invited = True
		self.worker_queue.put(ProvisioningEvent.Invite)

	def __del__(self):
		if self.pb_bearer:
			self.pb_bearer.close(pb_generic.LinkCloseReason.Fail)

	def __str__(self) -> str:
		return f"{self.device_uuid}"


class UnprovisionedDevicesCollection:
	__slots__ = "unprovisioned_devices", "timeout"
	DEFAULT_TIMEOUT = datetime.timedelta(minutes=1)

	def __init__(self, timeout=DEFAULT_TIMEOUT):
		self.unprovisioned_devices = list()  # type: List[UnprovisionedDevice]
		self.timeout = timeout

	def add_beacon(self, new_beacon: beacon.UnprovisionedBeacon):
		for device in self.unprovisioned_devices:
			if device.device_uuid == new_beacon.dev_uuid:
				device.update_beacon(new_beacon)
				return device
		self.unprovisioned_devices.append(UnprovisionedDevice(new_beacon))
		return self.unprovisioned_devices[-1]

	def get(self, device_uuid: UUID) -> UnprovisionedDevice:
		for device in self.unprovisioned_devices:
			if device.device_uuid == device_uuid:
				return device
		raise LookupError(f"device {device_uuid} not found")

	def __getitem__(self, item) -> UnprovisionedDevice:
		return self.unprovisioned_devices[item]

	def flush_expired(self):
		oldest_date = datetime.datetime.now() - self.timeout
		self.unprovisioned_devices = filter(lambda a: a.last_seen > oldest_date, self.unprovisioned_devices)

	def __len__(self) -> int:
		return len(self.unprovisioned_devices)

	def __str__(self) -> str:
		return str([str(d) for d in self.unprovisioned_devices])


class Provisioner:
	DEFAULT_TIMEOUT_UNPROV = datetime.timedelta(minutes=1)

	def __init__(self, default_bearer: Optional[ProvisionerBearer],
				 timeout_unprov: object = DEFAULT_TIMEOUT_UNPROV) -> object:
		self.timeout_unprov = timeout_unprov
		self.pb_bearer = default_bearer
		self.incoming_pdus = queue.Queue()
		self.incoming_pdus_thread = threading.Thread(target=self.incoming_pdu_worker)
		self.incoming_pdus_thread.start()
		self.unprovisioned_devices = UnprovisionedDevicesCollection()

	def set_bearer(self, pb_bearer: ProvisionerBearer):
		self.pb_bearer = pb_bearer
		self.pb_bearer.recv_generic_prov_pdu = self.queue_incoming_pdu

	def incoming_pdu_worker(self):
		while True:
			item = self.incoming_pdus.get()
			print(item)
			if not item:
				break
			self.handle_pdu(item)
			self.incoming_pdus.task_done()

	def provision(self, device_uuid: UUID):
		device = self.unprovisioned_devices.get(device_uuid)
		device.open()
		device.invite()

	def queue_incoming_pdu(self, pdu: bytes):
		print(pdu)
		self.incoming_pdus.put(PDU.from_bytes(pdu))

	def handle_pdu(self, pdu: PDU):
		print(f"PDU TYPE: {pdu.pdu_type}")

	def handle_beacon(self, new_beacon: beacon.UnprovisionedBeacon) -> UnprovisionedDevice:
		return self.unprovisioned_devices.add_beacon(new_beacon)

import datetime
import enum
import math
import os
import queue
import struct
import threading
from typing import *
from uuid import UUID
from . import crypto, beacon, mesh, pb_generic


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
		pdu_type = PDUType(b[0] & 0x3F)
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


class Algorithms(enum.IntFlag):
	FIPSP256 = 0

	def check_enabled(self, algorithm: 'Algorithms'):
		return (1 << algorithm) & self == 1


class OOBSize(int):
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


OOBAction = Union[InputOOBAction, OutputOOBAction]


class Capabilities(PDU):
	STRUCT = struct.Struct("!BHBBBHBH")
	__slots__ = "number_of_elements", "algorithms", "public_key_type", "static_oob_type", "output_oob_size", \
				"output_oob_action", "input_oob_size", "input_oob_action"

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
		num_elems, algo, pub_key, static_oob, out_oob_size, out_oob_action, input_oob_size, input_oob_action = cls.STRUCT.unpack(
			b)
		return cls(num_elems, Algorithms(algo), pub_key, static_oob, OOBSize(out_oob_size),
				   OutputOOBAction(out_oob_action), OOBSize(input_oob_size), InputOOBAction(input_oob_action))


class PublicKeyOption(enum.IntEnum):
	NoOOB = 0
	YesOOB = 1


class AuthenticationMethod(enum.IntEnum):
	NoOOB = 0
	StaticOOB = 1
	OutputOOB = 2
	InputOOB = 3


AuthenticationAction = Union[OutputOOBAction, InputOOBAction]


class Start(PDU):
	STRUCT = struct.Struct("!BBBBB")
	__slots__ = "algorithm", "public_key", "authentication_method", "authentication_action", "authentication_size"

	def __init__(self, algorithm: Algorithms, public_key: PublicKeyOption, authentication_method: AuthenticationMethod,
				 authentication_action: AuthenticationAction, authentication_size: OOBSize):
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


class PublicKeyPDU(PDU):
	__slots__ = "public_key"

	def __init__(self, public_key: crypto.ECCKeyPoint):
		super().__init__(PDUType.PublicKey)
		self.public_key = public_key

	def parameters_to_bytes(self) -> bytes:
		return struct.pack("!32s32s", self.public_key.x.to_bytes(32, "big"), self.public_key.y.to_bytes(32, "big"))

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'PublicKeyPDU':
		print(f"public_key: {b.hex()}")
		x, y = struct.unpack("!32s32s", b)
		return cls(crypto.ECCKeyPoint(int.from_bytes(x, byteorder="big"), int.from_bytes(y, byteorder="big")))


class InputComplete(PDU):
	def __init__(self):
		super().__init__(PDUType.InputComplete)

	def parameters_to_bytes(self) -> bytes:
		return bytes()

	@classmethod
	def parameters_from_bytes(cls, b: bytes):
		if len(b) != 0:
			raise ValueError("input complete not empty")
		return cls()


class Confirmation(PDU):
	LEN = 16
	__slots__ = "cmac",

	def __init__(self, cmac: crypto.MAC):
		super().__init__(PDUType.Confirmation)
		self.cmac = cmac

	def parameters_to_bytes(self) -> bytes:
		return self.cmac

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'Confirmation':
		return cls(crypto.MAC(b))


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

	@classmethod
	def generate_random(cls) -> 'Random':
		return cls(os.urandom(cls.LEN))

	def __repr__(self) -> str:
		return self.random_data.hex()


class ProvisioningData:
	STRUCT = struct.Struct("!16sHBLH")
	__slots__ = "network_key", "key_index", "flags", "iv_index", "unicast_address"

	def __init__(self, network_key: crypto.NetworkKey, key_index: crypto.NetKeyIndex, flags: ProvisioningDataFlags,
				 iv_index: crypto.IVIndex,
				 unicast_address: mesh.UnicastAddress):
		self.network_key = network_key
		self.key_index = key_index
		self.flags = flags
		self.iv_index = iv_index
		self.unicast_address = unicast_address

	def to_bytes(self) -> bytes:
		return self.STRUCT.pack(self.network_key.key_bytes, self.key_index.value, self.flags.value, self.iv_index.value,
								self.unicast_address.value)

	def encrypt(self, key: crypto.SessionKey, nonce: crypto.SessionNonce) -> 'EncryptedProvisioningData':
		print(f"key: {key.hex()} nonce: {nonce.as_be_bytes().hex()}")
		data, mic = crypto.aes_ccm_encrypt(key, nonce, self.to_bytes(), mic_len=8 * 8)
		return EncryptedProvisioningData(data, mic)

	@classmethod
	def from_bytes(cls, b: bytes):
		key, index, flags, iv_index, addr = cls.STRUCT.unpack(b)
		return cls(crypto.NetworkKey(key), crypto.NetKeyIndex(index), ProvisioningDataFlags(flags), crypto.IVIndex(iv_index),
				   mesh.UnicastAddress(addr))


class EncryptedProvisioningData(PDU):
	MIC_LEN = 8
	DATA_LEN = 25
	__slots__ = "encrypted_data", "mic"

	def __init__(self, data: bytes, mic: mesh.MIC):
		super().__init__(PDUType.Data)
		if len(data) != self.DATA_LEN:
			raise ValueError(f"invalid data length (expected {self.DATA_LEN} got {len(data)}")
		if mic.mic_len() != self.MIC_LEN * 8:
			raise ValueError("invalid mic length")
		self.encrypted_data = data
		self.mic = mic

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'EncryptedProvisioningData':
		return cls(b[:cls.DATA_LEN], mesh.MIC(b[cls.DATA_LEN:]))

	def parameters_to_bytes(self) -> bytes:
		return self.encrypted_data + self.mic.bytes_be

	def decrypt(self, key: crypto.SessionKey, nonce: crypto.SessionNonce) -> 'ProvisioningData':
		return ProvisioningData.from_bytes(crypto.aes_ccm_decrypt(key, nonce, self.encrypted_data, self.mic))


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

class Complete(PDU):
	def __init__(self) -> None:
		super().__init__(PDUType.Complete)

	def parameters_to_bytes(self) -> bytes:
		return bytes()

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'Complete':
		assert len(b) == 0
		return cls()

pdu_classes[PDUType.Invite] = Invite
pdu_classes[PDUType.Capabilities] = Capabilities
pdu_classes[PDUType.Start] = Start
pdu_classes[PDUType.PublicKey] = PublicKeyPDU
pdu_classes[PDUType.InputComplete] = InputComplete
pdu_classes[PDUType.Confirmation] = Confirmation
pdu_classes[PDUType.Random] = Random
pdu_classes[PDUType.Data] = EncryptedProvisioningData
pdu_classes[PDUType.Confirmation] = Confirmation
pdu_classes[PDUType.Failed] = Failed
pdu_classes[PDUType.Complete] = Complete

def segment_pdu(pdu: PDU, max_mtu: int) -> Generator[pb_generic.GenericProvisioningPDU, None, None]:
	pdu_bytes = pdu.to_bytes()
	start_data_size = max_mtu - pb_generic.TransactionStartPDU.control_pdu_size()
	if start_data_size < 1:
		raise ValueError("MTU too small")

	max_continue_data_size = max_mtu - pb_generic.TransactionContinuationPDU.control_pdu_size()
	seg_n = (len(pdu_bytes) - start_data_size) // max_continue_data_size if len(pdu_bytes) > start_data_size else 0
	if start_data_size + max_continue_data_size * seg_n < len(pdu_bytes):
		seg_n += 1
	start_data_size = len(pdu_bytes) if start_data_size > len(pdu_bytes) else start_data_size
	fcs = pb_generic.fcs_calc(pdu_bytes)
	yield pb_generic.TransactionStartPDU(seg_n, len(pdu_bytes), fcs, pdu_bytes[:start_data_size])
	for seg_i in range(seg_n):
		start_i = start_data_size + seg_i * max_continue_data_size
		end_i = start_i + max_continue_data_size
		yield pb_generic.TransactionContinuationPDU(seg_i + 1, pdu_bytes[start_i:end_i])


class Reassembler:
	def __init__(self, total_length: int, seg_n: int, fcs: int, mtu: int, transaction_number: int):
		self.total_length = total_length
		self.fcs = fcs
		self.mtu = mtu
		self.start_seg_len = mtu - pb_generic.TransactionStartPDU.control_pdu_size()
		self.continue_seg_len = mtu - pb_generic.TransactionContinuationPDU.control_pdu_size()
		self.seg_n = seg_n
		self.seg_mask = (2 ** (self.seg_n + 1)) - 1  # generate bit mask of length (seg_n + 1)
		self.segs_needed = self.seg_mask  # bit == 1 when need, bit == 0 when we receive said segment
		self.transaction_number = transaction_number
		self.data = bytearray(total_length)  # generate zeroed data array

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
		pos += self.continue_seg_len * (seg_i - 1)
		return pos

	def insert_segment(self, seg_i: int, data: bytes):
		if seg_i != self.seg_n:  # if segment is not the last seg
			if seg_i == 0 and len(data) != self.start_seg_len:
				raise ValueError("transaction start pdu too small")
			if seg_i > 0 and len(data) != self.continue_seg_len:
				raise ValueError("transaction continue pdu too small")
		pos = self.seg_pos(seg_i)
		if pos + len(data) > self.total_length:
			raise ValueError(
				f"data out of bounds. seg_i: {seg_i} pos: {pos} data_len: {len(data)} expect_total: {self.total_length}")
		# insert segment data
		for i in range(len(data)):
			self.data[i + pos] = data[i]
		# mark segment received
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
			raise ValueError(f"incorrect transaction number ({pdu.transaction_number}!={self.transaction_number})")
		if pdu.gpcf() == pb_generic.GPCF.TRANSACTION_START:
			self.insert_segment(0, pdu.payload())
		else:
			self.insert_segment(cast(pb_generic.TransactionContinuationPDU, pdu).segment_index, pdu.payload())

	def is_done(self) -> bool:
		return self.segs_needed == 0


class ProvisionerBearer:
	START_TRANSACTION_NUMBER = mesh.TransactionNumber(0x00)
	END_TRANSACTION_NUMBER = mesh.TransactionNumber(0x7F)

	def __init__(self):
		self.message_ack_cv = threading.Condition()
		self.message_did_ack = False
		self.transaction_assembler = None  # type: Optional[Reassembler]
		self.transaction_number = self.START_TRANSACTION_NUMBER
		self.incoming_transaction_number = self.END_TRANSACTION_NUMBER + 1
		self.recv_prov_pdu: Optional[Callable[[PDU, ], None]] = None

	def open(self):
		raise NotImplementedError()

	def mtu(self) -> int:
		raise NotImplementedError()

	def wait_for_ack(self, timeout: Optional[float] = None) -> bool:
		with self.message_ack_cv:
			return self.message_ack_cv.wait(timeout)

	def message_ackked(self):
		self.message_did_ack = True
		if self.transaction_number >= self.END_TRANSACTION_NUMBER:
			self.transaction_number = self.END_TRANSACTION_NUMBER
		else:
			self.transaction_number += 1
		with self.message_ack_cv:
			self.message_ack_cv.notify_all()

	def close(self, reason: pb_generic.LinkCloseReason):
		raise NotImplementedError()

	def send_prov_pdu(self, pdu: PDU):
		self.send_generic_prov_pdus(segment_pdu(pdu, self.mtu()))

	def send_generic_prov_pdus(self, pdus: Iterator[pb_generic.GenericProvisioningPDU]):
		raise NotImplementedError()

	def handle_transaction_start(self, start_pdu: pb_generic.TransactionStartPDU):
		if self.transaction_assembler and self.transaction_assembler.transaction_number == start_pdu.transaction_number:
			return  # we already started this transaction
		# FIXME: start_pdu.transaction_number != 0?
		if start_pdu.transaction_number != 0 and start_pdu.transaction_number < self.incoming_transaction_number:
			return  # old transaction
		self.incoming_transaction_number = start_pdu.transaction_number
		self.transaction_assembler = Reassembler.from_start_pdu(start_pdu, self.mtu())

	def recv_generic_prov_pdu(self, incoming_pdu: pb_generic.GenericProvisioningPDU):
		if incoming_pdu.gpcf() == pb_generic.GPCF.TRANSACTION_ACK:
			if incoming_pdu.transaction_number == self.transaction_number:
				self.message_ackked()
				return

		if incoming_pdu.gpcf() == pb_generic.GPCF.TRANSACTION_START:
			self.handle_transaction_start(cast(pb_generic.TransactionStartPDU, incoming_pdu))
		elif incoming_pdu.gpcf() == pb_generic.GPCF.TRANSACTION_CONTINUE:
			if not self.transaction_assembler:
				# no reassembler so probably stale continue
				return
			self.transaction_assembler.insert_pdu(incoming_pdu)
		if self.transaction_assembler and self.transaction_assembler.is_done():
			pdu_data = self.transaction_assembler.payload()
			self.send_generic_prov_pdus([self.transaction_assembler.ack()])
			if self.incoming_transaction_number.value >= 0xFF:
				self.transaction_number = self.END_TRANSACTION_NUMBER + 1
			else:
				self.incoming_transaction_number += 1
			self.recv_prov_pdu(PDU.from_bytes(pdu_data))
			self.transaction_assembler = None

	def __del__(self):
		self.close(pb_generic.LinkCloseReason.Fail)


class AuthValue:
	AUTH_VALUE_LEN = 16

	def __init__(self, oob_type: OOBAction, oob_data: Union[bytes, int, str]):
		self.oob_type = oob_type
		self.oob_data = oob_data

	def to_bytes(self) -> bytes:
		if self.oob_type == InputOOBAction.NoAction or self.oob_type == OutputOOBAction.NoAction:
			return bytes(self.AUTH_VALUE_LEN)
		raise NotImplementedError()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'AuthValue':
		pass

	@classmethod
	def no_oob(cls) -> 'AuthValue':
		return AuthValue(InputOOBAction(0), bytes())


ConfirmationProvisioner = NewType("ConfirmationProvisioner", bytes)
ConfirmationDevice = NewType("ConfirmationDevice", bytes)


class ConfirmationKey(crypto.Key):
	def __init__(self, key_bytes: bytes):
		super().__init__(bytearray(key_bytes))

	def confirm_provisioner(self, random_prov: bytes, auth_value: AuthValue) -> ConfirmationProvisioner:
		return ConfirmationProvisioner(crypto.aes_cmac(self, random_prov + auth_value.to_bytes()))

	def confirm_device(self, random_device: bytes, auth_value: AuthValue) -> ConfirmationDevice:
		return ConfirmationDevice(crypto.aes_cmac(self, random_device + auth_value.to_bytes()))


class ConfirmationSalt:
	__slots__ = "salt_bytes",

	def __init__(self, salt_bytes: bytes):
		self.salt_bytes = salt_bytes

	def salt(self) -> crypto.Salt:
		return crypto.Salt(self.salt_bytes)

	def to_key(self, ecdh_secret: crypto.ECDHSharedSecret) -> ConfirmationKey:
		return ConfirmationKey(crypto.k1(self.salt(), ecdh_secret, "prck".encode()))


class ConfirmationPackets:
	__slots__ = "prov_invite", "prov_capabilities", "prov_start", "prov_public_key", "device_public_key"

	def __init__(self):
		self.prov_invite: Optional[Invite] = None
		self.prov_capabilities: Optional[Capabilities] = None
		self.prov_start: Optional[Start] = None
		self.prov_public_key: Optional[PublicKeyPDU] = None
		self.device_public_key: Optional[PublicKeyPDU] = None

	def is_ready(self) -> bool:
		for slot in self.__slots__:
			if getattr(self, slot) is None:
				return False
		return True

	def confirmation_input(self) -> bytes:
		if not self.is_ready():
			raise ValueError("missing confirmation packets")
		return self.prov_invite.parameters_to_bytes() + self.prov_capabilities.parameters_to_bytes() + self.prov_start.parameters_to_bytes() + self.prov_public_key.parameters_to_bytes() + self.device_public_key.parameters_to_bytes()

	def confirmation_salt(self) -> ConfirmationSalt:
		inp = self.confirmation_input()
		print("input: ")
		print(f'[0]   {inp[:64].hex()}')
		print(f'[64]  {inp[64:128].hex()}')
		print(f'[128] {inp[128:].hex()}')
		# assert len(inp) == 145, f"expect 145 byte long confirmation input, got {len(inp)}"
		return ConfirmationSalt(crypto.s1(inp))


# the numbers don't matter
class ProvisioningEvent(enum.IntEnum):
	Open = 1
	Invite = 2
	Connected = 3
	Fail = 4
	Capabilities = 5
	Start = 6
	DevicePublicKey = 7
	SendProvPublicKey = 8
	Authenticate = 9
	ProvisionerRandom = 10
	DeviceConfirmation = 11
	Distribute = 12
	Done = 13


class UnprovisionedDevice:
	def __init__(self, first_beacon: beacon.UnprovisionedBeacon):
		self.last_seen = first_beacon.last_seen
		self.device_uuid = first_beacon.dev_uuid
		self.last_beacon = first_beacon
		self.pb_bearer: Optional[ProvisionerBearer] = None
		self.invited = False
		self.connected = False
		self.provision_on_connect = False
		self.worker_queue = queue.Queue()
		self.worker = threading.Thread(target=self.worker_func)
		self.worker.start()
		self.algorithm: Optional[Algorithms] = None
		self.public_key_option = PublicKeyOption.NoOOB
		self.get_device_key_oob: Optional[Callable[UnprovisionedDevice, PublicKeyPDU]] = None
		self.auth_method: AuthenticationMethod = AuthenticationMethod.NoOOB
		self.auth_action: AuthenticationAction = OutputOOBAction.NoAction
		self.auth_size = OOBSize(0)
		self.auth_value = AuthValue.no_oob()
		self.private_key: Optional[crypto.ECCPrivateKey] = None
		self.confirmation_packets = ConfirmationPackets()
		self.confirmation_salt: Optional[ConfirmationSalt] = None
		self.capabilities: Optional[Capabilities] = None
		self.device_public_key: Optional[crypto.ECCPublicKey] = None
		self.shared_secret: Optional[crypto.ECDHSharedSecret] = None
		self.attention_timer = 5
		self.device_random: Optional[Random] = None
		self.prov_random: Optional[Random] = None
		self.device_confirmation: Optional[ConfirmationDevice] = None
		self.prov_confirmation: Optional[ConfirmationProvisioner] = None
		self.confirmation_key: Optional[ConfirmationKey] = None
		self.provision_salt: Optional[crypto.ProvisioningSalt] = None
		self.close_reason = pb_generic.LinkCloseReason.Timeout
		self.done_callback: Optional[Callable[UnprovisionedDevice, None]] = None
		self.get_provisioning_data: Optional[Callable[UnprovisionedDevice, ProvisioningData]] = None
		self.provisioning_data: Optional[ProvisioningData] = None
		self.last_event: Optional[ProvisioningEvent] = None
		self.event_condition = threading.Condition()
		self.primary_address: Optional[mesh.UnicastAddress] = None
		self.done = False
		self.device_key: Optional[crypto.DeviceKey] = None
		self.session_key: Optional[crypto.SessionKey] = None
		self.session_nonce: Optional[crypto.SessionNonce] = None
		self.failed_code: Optional[ErrorCode] = None
		self.failed_callback: Optional[Callable[[UnprovisionedDevice, ], None]] = None

	def _opened_event(self):
		self.connected = True
		self.worker_queue.put(ProvisioningEvent.Connected)

	def open(self):
		self.worker_queue.put(ProvisioningEvent.Open)

	def do_open(self):
		self.pb_bearer.open()
		self.worker_queue.put(ProvisioningEvent.Connected)

	def log_print(self, msg: str) -> None:
		print(msg)

	def start(self):
		self.worker_queue.put(ProvisioningEvent.Start)

	def handle_event(self, provisioning_event: ProvisioningEvent):
		self.last_event = provisioning_event
		if provisioning_event == ProvisioningEvent.Invite:
			self.log_print(f"inviting {self.device_uuid}")
			self.do_invite()
		elif provisioning_event == ProvisioningEvent.Open:
			self.log_print(f"opening {self.device_uuid}")
			self.do_open()
		elif provisioning_event == ProvisioningEvent.Connected:
			self.log_print(f"{self.device_uuid} connected!")
			if self.provision_on_connect:
				self.invite()
		elif provisioning_event == ProvisioningEvent.Capabilities:
			self.log_print(f"{self.device_uuid} capabilities received!")
			if self.provision_on_connect:
				self.start()
		elif provisioning_event == ProvisioningEvent.Start:
			self.log_print(f"{self.device_uuid} starting provision process...")
			self.do_start()
		elif provisioning_event == ProvisioningEvent.DevicePublicKey:
			self.log_print(f"{self.device_uuid} got device public key! commencing ECDH...")
			self.shared_secret = self.private_key.make_shared_secret(self.device_public_key)
			if self.provision_on_connect:
				self.authenticate()
		elif provisioning_event == ProvisioningEvent.Authenticate:
			self.log_print(f"{self.device_uuid} authenticating")
			self.do_authentication()
		elif provisioning_event == ProvisioningEvent.ProvisionerRandom:
			self.log_print(f"{self.device_uuid} sending provisioning random: {self.prov_random}")
			self.do_send_random()
		elif provisioning_event == ProvisioningEvent.Distribute:
			self.log_print(f"{self.device_uuid} distributing provisioning data...")
			self.do_distribute()
		elif provisioning_event == ProvisioningEvent.Done:
			self.log_print(f"{self.device_uuid} is provisioned! address: {self.primary_address}")
			self.done_callback()
		elif provisioning_event == ProvisioningEvent.Fail:
			self.log_print(f"{self.device_uuid} Failed! Error Code: {self.failed_code}")
			if self.failed_callback:
				self.failed_callback(self)

		with self.event_condition:
			self.event_condition.notify()

	def do_distribute(self):
		self.provision_salt = crypto.ProvisioningSalt(
			crypto.s1(self.confirmation_salt.salt_bytes + self.prov_random.random_data + self.device_random.random_data))
		self.session_key = crypto.SessionKey.from_secret(self.shared_secret, self.provision_salt)
		self.session_nonce = crypto.SessionNonce.from_secret(self.shared_secret, self.provision_salt)
		if not self.get_provisioning_data:
			raise RuntimeError("no way to get provisioning data (callable None)")
		self.device_key = crypto.DeviceKey.from_salt_and_secret(self.provision_salt, self.shared_secret)
		data: ProvisioningData = self.get_provisioning_data(self)
		self.primary_address = data.unicast_address
		self.pb_bearer.send_prov_pdu(data.encrypt(self.session_key, self.session_nonce))

	def check_confirmation(self):
		if self.prov_confirmation is None:
			raise ValueError("provisioner confirmation missing")
		if self.device_confirmation is None:
			raise ValueError("device confirmation missing")
		# TODO: CHECK CONFIRMATIONS
		random_and_auth: bytes = bytes(self.device_random.random_data + self.auth_value.to_bytes())
		print(random_and_auth)
		computed_device_confirmation = crypto.aes_cmac(self.confirmation_key, random_and_auth)
		if computed_device_confirmation != self.device_confirmation:
			self.bad_auth()
			return

		# Good auth
		self.worker_queue.put(ProvisioningEvent.Distribute)

	def disconnect(self) -> None:
		if self.connected:
			self.connected = False
			self.pb_bearer.close(self.close_reason)
			self.worker_queue.put(ProvisioningEvent.Disconnected)

	def bad_auth(self) -> None:
		self.log_print(f"{self.device_uuid} BAD AUTH VAULE! DISCONNECTING")
		self.close_reason = pb_generic.LinkCloseReason.Fail
		self.disconnect()

	def do_authentication(self):
		if self.shared_secret is None:
			raise ValueError("ECDH shared secret is required for authentication")
		if not self.confirmation_packets.is_ready():
			raise ValueError("have not sent or received all confirmation PDUs")
		self.prov_random = Random.generate_random()
		self.confirmation_salt = self.confirmation_packets.confirmation_salt()
		self.confirmation_key = self.confirmation_salt.to_key(self.shared_secret)
		self.prov_confirmation = crypto.aes_cmac(self.confirmation_key,
												 self.prov_random.random_data + self.auth_value.to_bytes())
		self.pb_bearer.send_prov_pdu(Confirmation(self.prov_confirmation))

	def authenticate(self):
		self.worker_queue.put(ProvisioningEvent.Authenticate)

	def do_invite(self):
		pdu = Invite(self.attention_timer)
		self.confirmation_packets.prov_invite = pdu
		self.pb_bearer.send_prov_pdu(pdu)

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
		pdu = Start(self.algorithm, self.public_key_option, self.auth_method, self.auth_action, self.auth_size)
		self.confirmation_packets.prov_start = pdu
		self.pb_bearer.send_prov_pdu(pdu)

		# Send public key after starting
		self.do_send_public_key()

	def worker_func(self):
		while True:
			print("start get")
			item = self.worker_queue.get()
			print(item)
			if not item:
				break
			try:
				self.handle_event(item)
			finally:
				self.disconnect()
			self.worker_queue.task_done()

	def do_send_random(self):
		if self.prov_random is None:
			raise ValueError("missing provisioner random")
		self.pb_bearer.send_prov_pdu(self.prov_random)

	def _get_oob_public_key(self) -> None:
		if self.public_key_option == PublicKeyOption.NoOOB:
			raise ValueError("public key option is NoOOB")
		if self.get_device_key_oob is None:
			raise ValueError("no get_device_key_oob function define")
		self.handle_public_key(self.get_device_key_oob(self))

	def do_send_public_key(self):
		self.private_key = crypto.ECCPrivateKey.generate()
		if self.public_key_option == PublicKeyOption.YesOOB:
			self._get_oob_public_key()
		pdu = PublicKeyPDU(self.private_key.public_key().point)
		self.confirmation_packets.prov_public_key = pdu
		self.pb_bearer.send_prov_pdu(pdu)

	def handle_capabilities(self, pdu: Capabilities):
		self.capabilities = pdu
		self.confirmation_packets.prov_capabilities = pdu
		self.worker_queue.put(ProvisioningEvent.Capabilities)

	def handle_public_key(self, pdu: PublicKeyPDU):
		self.device_public_key = crypto.ECCPublicKey.from_point(pdu.public_key)
		self.confirmation_packets.device_public_key = pdu
		self.worker_queue.put(ProvisioningEvent.DevicePublicKey)

	def recv_pdu(self, pdu: PDU):
		print(pdu.pdu_type)
		self.last_seen = datetime.datetime.now()
		if pdu.pdu_type == PDUType.Capabilities:
			self.handle_capabilities(cast(Capabilities, pdu))
		elif pdu.pdu_type == PDUType.PublicKey:
			self.handle_public_key(cast(PublicKeyPDU, pdu))
		elif pdu.pdu_type == PDUType.Confirmation:
			self.handle_confirmation(cast(Confirmation, pdu))
		elif pdu.pdu_type == PDUType.Random:
			self.handle_random(cast(Random, pdu))
		elif pdu.pdu_type == PDUType.Complete:
			self.handle_complete()
		elif pdu.pdu_type == PDUType.Failed:
			self.handle_failed(cast(Failed, pdu).error_code)
		else:
			raise ValueError(f"unhandled pdu type {pdu.pdu_type}")

	def handle_failed(self, error_code: ErrorCode) -> None:
		self.failed_code = error_code
		self.close_reason = pb_generic.LinkCloseReason.Fail
		self.worker_queue.put(ProvisioningEvent.Fail)
		self.disconnect()

	def handle_complete(self) -> None:
		self.done = True
		self.worker_queue.put(ProvisioningEvent.Done)

	def handle_random(self, random: Random) -> None:
		self.device_random = random
		self.check_confirmation()

	def handle_confirmation(self, confirmation: Confirmation) -> None:
		self.device_confirmation = confirmation.cmac
		self.worker_queue.put(ProvisioningEvent.ProvisionerRandom)

	def set_bearer(self, pb_bearer: ProvisionerBearer):
		self.pb_bearer = pb_bearer
		pb_bearer.recv_prov_pdu = self.recv_pdu

	def update_beacon(self, new_beacon: beacon.UnprovisionedBeacon):
		if new_beacon.dev_uuid != self.device_uuid:
			raise ValueError(f"new beacon dev_uuid does not match set uuid {new_beacon.dev_uuid} != {self.device_uuid}")
		if new_beacon.last_seen < self.last_seen:
			raise ValueError("incoming beacon is older than last_seen")  # beacon is old
		self.last_seen = new_beacon.last_seen
		self.last_beacon = new_beacon
		self.device_uuid = new_beacon.dev_uuid

	def invite(self):
		self.invited = True
		self.worker_queue.put(ProvisioningEvent.Invite)

	def __enter__(self) -> None:
		if self.connected:
			raise RuntimeError("device already connected")
		self.open()

	def __exit__(self, *_extra) -> None:
		if self.connected:
			self.disconnect()

	def __del__(self):
		if self.pb_bearer:
			self.pb_bearer.close(pb_generic.LinkCloseReason.Fail)

	def __str__(self) -> str:
		return f"{self.device_uuid}"


class UnprovisionedDevicesCollection:
	__slots__ = "unprovisioned_devices", "timeout", "on_new_device"
	DEFAULT_TIMEOUT = datetime.timedelta(minutes=1)

	def __init__(self, timeout=DEFAULT_TIMEOUT):
		self.unprovisioned_devices: List[UnprovisionedDevice] = list()
		self.timeout = timeout
		self.on_new_device: Optional[Callable[[UnprovisionedDevice, ], None]] = None

	def add_new_device(self, new_beacon: beacon.UnprovisionedBeacon) -> None:
		new_device = UnprovisionedDevice(new_beacon)
		self.unprovisioned_devices.append(new_device)
		if self.on_new_device:
			self.on_new_device(new_device)

	def add_beacon(self, new_beacon: beacon.UnprovisionedBeacon):
		for device in self.unprovisioned_devices:
			if device.device_uuid == new_beacon.dev_uuid:
				device.update_beacon(new_beacon)
				return device
		self.add_new_device(new_beacon)
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

	def __init__(self) -> None:
		self.unprovisioned_devices = UnprovisionedDevicesCollection()
		self.get_provisioning_data: Optional[Callable[UnprovisionedDevice, ProvisioningData]] = None
		self.failed_callback: Optional[Callable[UnprovisionedDevice, None]] = None

	def provision(self, device_uuid: UUID) -> UnprovisionedDevice:
		device = self.unprovisioned_devices.get(device_uuid)
		device.provision_on_connect = True
		device.get_provisioning_data = self.get_provisioning_data
		device.failed_callback = self.failed_callback
		device.open()
		return device

	def handle_beacon(self, new_beacon: beacon.UnprovisionedBeacon) -> UnprovisionedDevice:
		return self.unprovisioned_devices.add_beacon(new_beacon)

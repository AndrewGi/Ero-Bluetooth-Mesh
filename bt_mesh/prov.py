import datetime
import enum
import struct
from typing import Union, Optional
from uuid import UUID

from bt_mesh import crypto, bearer, beacon


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


class PDU:
	__slots__ = "pdu_type", "parameters"

	def __init__(self, pdu_type: PDUType, parameters: bytes):
		if pdu_type > 0x1F:
			raise ValueError(f"pdu type too high {pdu_type}")
		self.pdu_type = pdu_type
		self.parameters = parameters

	def to_bytes(self):
		return bytes([self.pdu_type]) + self.parameters.to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'PDU':
		return cls(PDUType(b[0]), b[1:])


class PDUParameters:
	def to_bytes(self) -> bytes:
		raise NotImplementedError()

	@classmethod
	def from_bytes(cls, b: bytes):
		raise NotImplementedError()

	@staticmethod
	def pdu_type() -> PDUType:
		raise NotImplementedError()

	def to_pdu(self) -> PDU:
		return PDU(self.pdu_type(), self.to_bytes())

	@classmethod
	def from_pdu(cls, pdu: PDU):
		if pdu.pdu_type != cls.pdu_type():
			raise ValueError(f"wrong opcode. expected: {cls.pdu_type()} got {pdu.pdu_type}")
		return cls(pdu.parameters)


class Invite:
	__slots__ = "attention_duration",

	def __init__(self, attention_duration: int):
		self.attention_duration = attention_duration

	def to_byte(self) -> bytes:
		return bytes([self.attention_duration])

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Invite':
		return cls(b[0])


class Algorithms(enum.IntEnum):
	FIPSP256 = 0


class OOBSize(enum.IntEnum):
	pass


class OutputOOBAction(enum.IntEnum):
	Blink = 0x01
	Beep = 0x02
	Vibrate = 0x04
	OutputNumeric = 0x08
	OutputAlphanumeric = 0x0F


class InputOOBAction(enum.IntEnum):
	Push = 0x01
	Twist = 0x02
	InputNumber = 0x04
	InputAlphanumeric = 0x08


class Capabilities:
	STRUCT = struct.Struct("!BHBBBHBH")
	__slots__ = "number_of_elements", "algorithms", "public_key_type", "static_oob_type", "output_oob_size", "output_oob_action", "input_oob_size", "input_oob_action"

	def __init__(self, number_of_elements: int, algorithms: Algorithms, public_key_type: bool,
				 static_oob_type: bool, output_oob_size: OOBSize, output_oob_action: OutputOOBAction,
				 input_oob_size: OOBSize, input_oob_action: InputOOBAction):
		self.number_of_elements = number_of_elements
		self.algorithms = algorithms
		self.public_key_type = public_key_type
		self.static_oob_type = static_oob_type
		self.output_oob_size = output_oob_size
		self.output_oob_action = output_oob_action
		self.input_oob_size = input_oob_size
		self.input_oob_action = input_oob_action

	def to_bytes(self) -> bytes:
		return self.STRUCT.pack(self.number_of_elements, self.algorithms, self.public_key_type, self.static_oob_type,
								self.output_oob_size, self.output_oob_action, self.input_oob_size, self.input_oob_action)

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Capabilities':
		return cls(cls.STRUCT.unpack(b))

class PublicKey(enum.IntEnum):
	NoOOB = 0
	YesOOB = 1

class AuthenticationMethod(enum.IntEnum):
	NoOOB = 0
	StaticOOB = 1
	OutputOOB = 2
	InputOOB = 3

AuthenticationMethod = Union[OutputOOBAction, InputOOBAction]

class Start:
	STRUCT = struct.Struct("!BBBBB")
	__slots__ = "algorithm", "public_key", "authentication_method", "authentication_action", "authentication_size"
	def __init__(self, algorithm: Algorithms, public_key: PublicKey, authentication_method: AuthenticationMethod, authentication_action: AuthenticationMethod, authentication_size: OOBSize):
		self.algorithm = algorithm
		self.public_key = public_key
		self.authentication_method = authentication_method
		self.authentication_action = authentication_action
		self.authentication_size = authentication_size

	def to_bytes(self) -> bytes:
		return self.STRUCT.pack(self.algorithm, self.public_key, self.authentication_method, self.authentication_action, self.authentication_size)

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Start':
		return cls(*cls.STRUCT.unpack(b))


class PublicKey:
	__slots__ = "x", "y"
	def __init__(self, x: crypto.PublicKeyXY, y: crypto.PublicKeyXY):
		self.x = x
		self.y = y

	def to_bytes(self) -> bytes:
		return struct.pack("32s32s", self.x, self.y)

	@classmethod
	def from_bytes(cls, b: bytes) -> 'PublicKey':
		return cls(*struct.unpack("32s32s", b))

class InputComplete:
	pass

class Confirmation:
	LEN = 16
	__slots__ = "data"
	def __init__(self, data: bytes):
		self.data = data

class Data:
	__slots__ = "encrypted_data", "mic"


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
		self.error_code = error_code

	def to_bytes(self) -> bytes:
		return self.error_code.to_bytes(1, byteorder="big")

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Failed':
		return cls(ErrorCode(int.from_bytes(b[:1], byteorder="big")))

class ProvisionerBearer(bearer.Bearer):
	pass

class Provisioner:
	DEFAULT_TIMEOUT_UNPROV = datetime.timedelta(minutes=1)
	def __init__(self, default_bearer: Optional[ProvisionerBearer], timeout_unprov: object = DEFAULT_TIMEOUT_UNPROV) -> object:
		self.timeout_unprov = timeout_unprov
		self.default_bearer = default_bearer
		self.unprovisioned_devices = list() # type: List[beacon.UnprovisionedBeacon]


	def _flush_beacons(self, timeout: Optional[datetime.timedelta] = None):
		if not timeout:
			timeout = self.timeout_unprov
		for b in self.unprovisioned_devices:
			if (b.last_seen + timeout) < datetime.datetime.now():
				self.unprovisioned_devices.remove(b)

	def handle_beacon(self, new_beacon: beacon.UnprovisionedBeacon):
		self._flush_beacons()
		self.unprovisioned_devices.append(new_beacon)

	def provision(self, device_uuid: UUID):
		pass
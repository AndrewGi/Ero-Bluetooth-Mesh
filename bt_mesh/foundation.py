from . import access
from .mesh import *
from .serialize import *
from typing import *
import abc


class CompositionDataPage(abc.ABC, ByteSerializable):

	@classmethod
	def from_bytes(cls, b: bytes):
		raise NotImplementedError

	def to_bytes(self) -> bytes:
		raise NotImplementedError()


class LogField(U8):

	def __init__(self, raw: int):
		if 0 <= raw <= 0x10:
			super().__init__(raw)
		else:
			raise ValueError(f"log field raw value must be 0<={raw}<=0x10")

	@classmethod
	def map(cls, value: int) -> 'LogField':
		if not 0 <= value <= 0xFFFF:
			raise ValueError(f"value must be 0<={value}<=0xFFFF")
		return cls(value.bit_length())

	def range(self) -> Tuple[int, int]:
		if self.value == 0:
			return 0, 0
		return 2 ** (self.value - 1), 2 ** self.value - 1


class StepResolution(IntFlag):
	HundredMilliseconds = 0
	OneSecond = 1
	TenSeconds = 2
	TenMinutes = 3

	def to_milliseconds(self) -> int:
		if self == self.HundredMilliseconds:
			return 100
		elif self == self.OneSecond:
			return 1 * 1000
		elif self == self.TenSeconds:
			return 10 * 1000
		elif self == self.TenMinutes:
			return 10 * 60 * 1000


class PublishPeriod(ByteSerializable):
	__slots__ = "steps_num", "steps_res"

	def __init__(self, steps_num: int, steps_res: StepResolution) -> None:
		if 0 <= steps_num < 0x40:
			self.steps_num = steps_num
			self.steps_res = steps_res
		raise ValueError(f"step num must be 0<={steps_res}<0x40")

	def period(self) -> int:
		return self.steps_res.to_milliseconds() * self.steps_num

	def to_bytes(self) -> bytes:
		return (((self.steps_res & 0x3) << 6) | (self.steps_num & 0x3F)).to_bytes(1, byteorder="little")

	@classmethod
	def from_bytes(cls, b: bytes) -> 'ByteSerializable':
		if len(b) != 1:
			raise ValueError(f"len of bytes should be 1 not {len(b)}")
		steps_num = b[0] & 0x3F
		steps_res = StepResolution(b[0] >> 6)
		return cls(steps_num, steps_res)


class SIGModelID(U16, Enum):
	ConfigurationServer = U16(0x0001)
	ConfigurationClient = U16(0x0002)
	HealthServer = U16(0x0003)
	HealthClient = U16(0x0004)


class VendorModelID(ByteSerializable):
	pass


class ElementDescriptor(ByteSerializable):
	__slots__ = "location", "sig_models", "vendor_models"

	def __init__(self, location: LocationDescriptor, sig_models: List[SIGModelID], vendor_models: List[VendorModelID]):
		self.location = location
		self.sig_models = sig_models
		self.vendor_models = vendor_models


class Elements:
	__slots__ = "elements",

	def __init__(self, elements: List[ElementDescriptor]):
		self.elements = elements


class CompositionDataPage0(CompositionDataPage):
	__slots__ = "cid", "pid", "vid", "crpl", "features", "elements"

	def __init__(self, cid: CompanyID, pid: ProductID, vid: VersionID, crpl: int, features: Features,
				 elements: Elements):
		self.cid = cid
		self.pid = pid
		self.vid = vid
		self.crpl = crpl
		self.features = features
		self.elements = elements


class Fault(U8, Enum):
	NoFault = U8(0x00)
	BatteryLow = U8(0x02)
	SupplyVoltageTooLow = U8(0x04)
	SupplyVoltageTooHigh = U8(0x06)
	PowerSupplyInterrupted = U8(0x08)
	NoLoad = U8(0x0A)
	Overload = U8(0x0C)
	Overheat = U8(0x0E)
	Condensation = U8(0x10)
	Vibration = U8(0x12)
	Configuration = 14
	ElementNotCalibrated = U8(0x16)
	Memory = U8(0x18)
	SelfTest = U8(0x1A)
	InputTooLow = U8(0x1C)
	InputTooHigh = U8(0x1E)
	InputNoChange = U8(0x20)
	ActuatorBlocked = U8(0x22)
	HousingOpened = U8(0x24)
	Tamper = U8(0x26)
	DeviceMoved = U8(0x28)
	DeviceDropped = U8(0x2A)
	Overflow = U8(0x2C)
	Empty = U8(0x2E)
	InternalBus = U8(0x30)
	MechanismJammed = U8(0x32)
	VendorStart = U8(0x80)


class Status(U8, Enum):
	Success = U8(0x00)
	InvalidAddress = U8(0x01)
	InvalidModel = U8(0x02)
	InvalidAppKeyIndex = U8(0x03)
	InvalidNetKeyIndex = U8(0x04)
	InsufficientResources = U8(0x05)
	KeyIndexAlreadyStored = U8(0x06)
	InvalidPublishParameters = U8(0x07)
	NotASubscribeModel = U8(0x08)
	StorageFailure = U8(0x09)
	FeatureNotSupported = U8(0x0A)
	CannotUpdate = U8(0x0B)
	CannotRemove = U8(0x0C)
	CannotBind = U8(0x0D)
	TemporarilyUnableToChangeState = U8(0x0E)
	CannotSet = U8(0x0F)
	UnspecifiedError = U8(0x10)
	InvalidBinding = U8(0x11)

SubscriptionAddress = Union[GroupAddress, VirtualAddress]


class SubscriptionList:
	__slots__ = "addresses",

	def __init__(self, addresses: List[SubscriptionAddress]):
		self.addresses = addresses


class ModelPublication:
	__slots__ = "address", "period", "appkey_index", "friendship_credentials_flag", "ttl", "retransmit"

	def __init__(self, address: Address, period: PublishPeriod, appkey_index: AppKeyIndex,
				 friendship_credentials_flag: bool,
				 ttl: TTL, retransmit: RetransmitParameters):
		self.address = address
		self.period = period
		self.appkey_index = appkey_index
		self.friendship_credentials_flag = friendship_credentials_flag
		self.ttl = ttl
		self.retransmit = retransmit


class NetKeyList(ByteSerializable):
	__slots__ = "indexed_list",
	def __init__(self, indexed_list: Dict[NetKeyIndex, crypto.NetKeyIndexSlot]):


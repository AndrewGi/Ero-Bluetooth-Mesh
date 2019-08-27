import struct

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
	def from_bytes(cls, b: bytes) -> 'PublishPeriod':
		if len(b) != 1:
			raise ValueError(f"len of bytes should be 1 not {len(b)}")
		steps_num = b[0] & 0x3F
		steps_res = StepResolution(b[0] >> 6)
		return cls(steps_num, steps_res)


class SIGModelID(U16, Enum):
	ConfigurationServer = 0x0001
	ConfigurationClient = 0x0002
	HealthServer = 0x0003
	HealthClient = 0x0004


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
	NoFault = 0x00
	BatteryLow = 0x02
	SupplyVoltageTooLow = 0x04
	SupplyVoltageTooHigh = 0x06
	PowerSupplyInterrupted = 0x08
	NoLoad = 0x0A
	Overload = 0x0C
	Overheat = 0x0E
	Condensation = 0x10
	Vibration = 0x12
	Configuration = 14
	ElementNotCalibrated = 0x16
	Memory = 0x18
	SelfTest = 0x1A
	InputTooLow = 0x1C
	InputTooHigh = 0x1E
	InputNoChange = 0x20
	ActuatorBlocked = 0x22
	HousingOpened = 0x24
	Tamper = 0x26
	DeviceMoved = 0x28
	DeviceDropped = 0x2A
	Overflow = 0x2C
	Empty = 0x2E
	InternalBus = 0x30
	MechanismJammed = 0x32
	VendorStart = 0x80


class Status(U8, Enum):
	Success = 0x00
	InvalidAddress = 0x01
	InvalidModel = 0x02
	InvalidAppKeyIndex = 0x03
	InvalidNetKeyIndex = 0x04
	InsufficientResources = 0x05
	KeyIndexAlreadyStored = 0x06
	InvalidPublishParameters = 0x07
	NotASubscribeModel = 0x08
	StorageFailure = 0x09
	FeatureNotSupported = 0x0A
	CannotUpdate = 0x0B
	CannotRemove = 0x0C
	CannotBind = 0x0D
	TemporarilyUnableToChangeState = 0x0E
	CannotSet = 0x0F
	UnspecifiedError = 0x10
	InvalidBinding = 0x11


SubscriptionAddress = Union[GroupAddress, VirtualAddress]


class SubscriptionList:
	__slots__ = "addresses",

	def __init__(self, addresses: List[SubscriptionAddress]):
		self.addresses = addresses


class ModelPublication(ByteSerializable):
	__slots__ = "element_address", "publish_address", "app_key_index", "credential_flag", "publish_ttl", "publish_period", \
				"publish_retransmit", "model_identifier", "net_key_index"

	def __init__(self, element_address: UnicastAddress, publish_address: Address, app_key_index: AppKeyIndex,
				 credential_flag: bool, publish_ttl: TTL, publish_period: PublishPeriod,
				 publish_retransmit: RetransmitParameters,
				 model_identifier: access.ModelIdentifier, net_key_index: Optional[NetKeyIndex] = None) -> None:
		self.element_address = element_address
		self.publish_address = publish_address
		self.app_key_index = app_key_index
		self.credential_flag = credential_flag
		self.publish_ttl = publish_ttl
		self.publish_period = publish_period
		self.publish_retransmit = publish_retransmit
		self.model_identifier = model_identifier
		self.net_key_index = net_key_index  # Not used in serialization but is used in model publishing

	# check what net key the app key is bound to

	def to_bytes(self) -> bytes:
		appkey_credential = U16(self.app_key_index.value | (self.credential_flag << AppKeyIndex.INDEX_LEN))
		publish_address = self.publish_address.uuid.bytes if isinstance(self.publish_address,
																		VirtualAddress) else self.publish_address.to_bytes()
		return self.element_address.to_bytes() + publish_address + appkey_credential.to_bytes() + \
			   self.publish_ttl.to_bytes() + self.publish_period.to_bytes() + self.publish_retransmit.to_bytes() + self.model_identifier.to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'ModelPublication':
		publish_address_size = 2 if len(b) < (2 + 2 + 1 + 1 + 1 + 4) else 16
		mp_struct = struct.Struct(f"<Hs{publish_address_size}HBBB")
		element_address, publish_address_raw, appkey_credential, publish_ttl, \
		publish_period, publish_retransmit = mp_struct.unpack(b)
		model_identifier = b[mp_struct.size:]
		publish_address = UnicastAddress.from_bytes(
			publish_address_raw) if publish_address_size == 2 else VirtualAddress(UUID(publish_address_raw))
		appkey_index = appkey_credential & ((1 << KeyIndex.INDEX_LEN) - 1)
		credential = (appkey_credential & (1 << KeyIndex.INDEX_LEN)) != 0
		return cls(UnicastAddress(element_address), publish_address, appkey_index, credential, TTL(publish_ttl),
				   PublishPeriod.from_bytes(publish_period.to_bytes(1, byteorder="little")),
				   RetransmitParameters.from_bytes(publish_retransmit.to_bytes(1, byteorder="little")),
				   access.ModelIdentifier.from_bytes(model_identifier))

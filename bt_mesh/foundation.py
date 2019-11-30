import struct
import time

from . import access, scheduler
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

	@staticmethod
	@abc.abstractmethod
	def page_number() -> U8:
		pass


class CRPL(U16):
	pass


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



class ElementID(U8):
	byteorder = "little"


class SIGModelID(access.ModelID):
	ConfigurationServer = 0x0001
	ConfigurationClient = 0x0002
	HealthServer = 0x0003
	HealthClient = 0x0004


class VendorModelID(ByteSerializable):
	def __init__(self, cid: CompanyID, model_id: access.ModelID) -> None:
		self.cid = cid
		self.model_id = model_id

	def to_bytes(self) -> bytes:
		return self.cid.to_bytes() + self.model_id.to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'VendorModelID':
		assert len(b) == 4
		return cls(CompanyID.from_bytes(b[0:2]), access.ModelID.from_bytes(b[2:4]))

	def __eq__(self, other: 'VendorModelID') -> bool:
		return self.cid == other.cid and self.model_id == other.model_id


class ElementDescriptor(ByteSerializable):
	__slots__ = "location", "sig_models", "vendor_models"

	def __init__(self, location: LocationDescriptor, sig_models: List[SIGModelID], vendor_models: List[VendorModelID]):
		self.location = location
		self.sig_models = sig_models
		self.vendor_models = vendor_models

	@classmethod
	def from_bytes(cls, b: bytes) -> 'ElementDescriptor':
		location = LocationDescriptor.from_bytes(b[:2])
		num_sig = b[2]
		num_vendor = b[3]
		start = 4
		sig_models: List[SIGModelID] = list()
		vendor_models: List[VendorModelID] = list()
		for i in range(num_sig):
			sig_models.append(SIGModelID.from_bytes(b[start + i * 2:start + (i + 1) * 2]))
		start += num_sig * SIGModelID.length
		for i in range(num_vendor):
			vendor_models.append(VendorModelID.from_bytes(b[start + i * 4:start + (i + 1) * 4]))
		return cls(location, sig_models, vendor_models)

	def to_bytes(self) -> bytes:
		return self.location.to_bytes() + U8(len(self.sig_models)).to_bytes() + U8(len(self.vendor_models)).to_bytes() \
			   + b"".join([sig_model.to_bytes() for sig_model in self.sig_models]) \
			   + b"".join([vendor_model.to_bytes() for vendor_model in self.vendor_models])

	def __len__(self) -> int:
		return 2 + 1 + 1 + len(self.sig_models) * SIGModelID.length + len(self.vendor_models) * 4

	def __eq__(self, other: 'ElementDescriptor') -> bool:
		return self.location == other.location and self.sig_models.sort() == other.sig_models.sort() \
			   and self.vendor_models.sort() == other.vendor_models.sort()


class Elements(ByteSerializable):
	__slots__ = "elements",

	def __init__(self, elements: List[ElementDescriptor]):
		self.elements = elements

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Elements':
		i = 0
		elements: List[ElementDescriptor] = list()
		while i < len(b):
			new_element = ElementDescriptor.from_bytes(b[i:])
			i += len(new_element)
			elements.append(new_element)
		return cls(elements)

	def to_bytes(self) -> bytes:
		return b"".join([element_descriptor.to_bytes() for element_descriptor in self.elements])

	def __eq__(self, other: 'Elements') -> bool:
		return self.elements.sort() == other.elements.sort()


class CompositionDataPage0(CompositionDataPage):
	__slots__ = "cid", "pid", "vid", "crpl", "features", "elements"

	def __init__(self, cid: CompanyID, pid: ProductID, vid: VersionID, crpl: CRPL, features: Features,
				 elements: Elements):
		self.cid = cid
		self.pid = pid
		self.vid = vid
		self.crpl = crpl
		self.features = features
		self.elements = elements

	def to_bytes(self) -> bytes:
		return self.cid.to_bytes() + self.pid.to_bytes() + self.vid.to_bytes() + self.crpl.to_bytes() \
			   + U16(self.features).to_bytes() + self.elements.to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'CompositionDataPage0':
		cid = CompanyID.from_bytes(b[0:2])
		pid = ProductID.from_bytes(b[2:4])
		vid = VersionID.from_bytes(b[4:6])
		crpl = CRPL.from_bytes(b[6:8])
		features = Features(U16.from_bytes(b[8:10]).value)
		elements = Elements.from_bytes(b[10:])
		return cls(cid, pid, vid, crpl, features, elements)

	def __eq__(self, other: 'CompositionDataPage0') -> bool:
		return self.cid == other.cid and self.pid == other.pid and self.vid == other.vid and self.crpl == other.crpl \
			   and self.features == other.features and self.elements == other.elements

	@staticmethod
	def page_number() -> U8:
		return U8(0)


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
				 publish_retransmit: PublishRetransmitParameters,
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
				   PublishRetransmitParameters.from_bytes(publish_retransmit.to_bytes(1, byteorder="little")),
				   access.ModelIdentifier.from_bytes(model_identifier))


class PublishRetransmitTask(scheduler.Task):
	def __init__(self, msg: access.AccessMessage, publication: PublishRetransmitParameters) -> None:
		super().__init__(0.0)
		self.msg = msg
		self.transmissions = publication.steps
		self.publication = publication
		self.fire_access: Optional[Callable[[access.AccessMessage, ], None]] = None

	def retransmit_msg(self) -> None:
		if self.transmissions <= 0:
			raise ValueError(f"{self.msg} out of retransmissions")
		if self.fire_access is None:
			raise ValueError(f"{self.msg} is missing fire_access")
		self.fire_access(self.msg)
		self.transmissions -= 1
		if self.transmissions > 0:
			self.schedule_next_publish()

	def schedule_next_publish(self) -> None:
		if self.transmissions <= 0:
			raise ValueError(f"{self.msg} out of retransmissions")
		self.reschedule(time.time() + self.publication.interval_ms() / 1000.0)

	def fire(self) -> None:
		self.retransmit_msg()


class PublishRetransmitter:

	def __init__(self) -> None:
		self.retransmit_scheduler = scheduler.Scheduler()
		self.fire_access: Optional[Callable[[access.AccessMessage, ], None]] = None

	def add_message(self, msg: access.AccessMessage, publication: PublishRetransmitParameters) -> None:
		task = PublishRetransmitTask(msg, publication)
		task.fire_access = self.fire_access
		task.retransmit_msg()  # first send.
		self.retransmit_scheduler.add_task(task)

from . import access
from .mesh import *
from typing import *
import abc


class CompositionDataPage(abc.ABC, ByteSerializable):

	@classmethod
	def from_bytes(cls):
		raise NotImplementedError

	def to_bytes(self) -> bytes:
		raise NotImplementedError()

class LogField:
	__slots__ = "raw",
	def __init__(self, raw: int):
		if 0<=raw<=0x10:
			self.raw = raw
		else:
			raise ValueError(f"log field raw value must be 0<={raw}<=0x10")

	@classmethod
	def map(cls, value: int) -> 'LogField':
		if not 0<=value<=0xFFFF:
			raise ValueError(f"value must be 0<={value}<=0xFFFF")
		return cls(value.bit_length())

	def range(self) -> Tuple[int, int]:
		if self.raw == 0:
			return 0, 0
		return 2 ** (self.raw - 1), 2 ** self.raw - 1


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
		if 0<=steps_num<0x40:
			self.steps_num = steps_num
			self.steps_res = steps_res
		raise ValueError(f"step num must be 0<={steps_res}<0x40")

	def period(self) -> int:
		return self.steps_res.to_milliseconds() * self.steps_num

	def to_bytes(self) -> bytes:

class SIGModelID(IntEnum):
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
	def __init__(self, cid: CompanyID, pid: ProductID, vid: VersionID, crpl: int, features: Features, elements: Elements):
		self.cid = cid
		self.pid = pid
		self.vid = vid
		self.crpl = crpl
		self.features = features
		self.elements = elements

class Fault(IntEnum):
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



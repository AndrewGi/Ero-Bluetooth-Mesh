from .hci import *


class LocalName(ByteSerializable):
	__slots__ = "name",
	MAX_LEN = 248

	def __init__(self, name: str) -> None:
		self.name = name

	def to_bytes(self) -> bytes:
		out = self.name.encode("utf-8")
		if len(out) > self.MAX_LEN:
			raise OverflowError(f"name length {self.MAX_LEN}>{len(out)}")
		return out

	@classmethod
	def from_bytes(cls, b: bytes) -> 'LocalName':
		if len(b) < cls.MAX_LEN:
			b = b[:-1]
		if len(b) > cls.MAX_LEN:
			raise OverflowError(f"name length {cls.MAX_LEN}>{len(b)}")
		return cls(b.decode("utf-8"))


class AdvertisingType(U8le, enum.Enum):
	ADV_IND = 0x00
	ADV_DIRECT_IND = 0x01
	ADV_SCAN_IND = 0x02
	ADV_NONCONN_IND = 0x03


class AddressType(U8le, enum.Enum):
	PublicDeviceAddress = 0x00
	RandomDeviceAddress = 0x01


class AdvertisingPeriod(U16le):
	pass


class DirectAddress(U24):
	byteorder = "little"


class ChannelMap(U8le, enum.Flag):
	Enable37 = 0
	Enable38 = 1
	Enable39 = 2


class FilterPolicy(U8le, enum.Enum):
	ScanAnyConnectAny = 0x00
	ScanWhitelistConnectAny = 0x01
	ScanAnyConnectWhitelist = 0x02
	ScanWhiteListConnectWhitelist = 0x03


class SetAdvertisingParameters(CommandParameters):
	Opcode = Opcode.from_ocf(LEControllerOpcode.SetAdvertisingParameters)
	__slots__ = "interval_min", "interval_max", "advertising_type", "own_address_type", "direct_address_type" \
		, "direct_address", "channel_map", "filter_policy"

	def __init__(self, interval_min: AdvertisingPeriod, interval_max: AdvertisingPeriod,
				 advertising_type: AdvertisingType,
				 own_address_type: AddressType, direct_address_type: AddressType, direct_address: DirectAddress,
				 channel_map: ChannelMap, filter_policy: FilterPolicy) -> None:
		self.interval_min = interval_min
		self.interval_max = interval_max
		self.advertising_type = advertising_type
		self.own_address_type = own_address_type
		self.direct_address_type = direct_address_type
		self.direct_address = direct_address
		self.channel_map = channel_map
		self.filter_policy = filter_policy

	def parameters_to_bytes(self) -> bytes:
		return self.interval_min.to_bytes() + self.interval_max.to_bytes() + self.advertising_type.to_bytes() \
			   + self.own_address_type.to_bytes() + self.direct_address.to_bytes() + self.channel_map.to_bytes() \
			   + self.filter_policy.to_bytes()

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'SetAdvertisingParameters':
		interval_min = AdvertisingPeriod.from_bytes(b[0:2])
		interval_max = AdvertisingPeriod.from_bytes(b[2:4])
		advertising_type = AdvertisingType.from_bytes(b[4:5])
		own_address_type = AddressType.from_bytes(b[5:6])
		direct_address_type = AddressType.from_bytes(b[6:7])
		direct_address = DirectAddress.from_bytes(b[7:13])
		channel_map = ChannelMap.from_bytes(b[13:14])
		filter_policy = FilterPolicy.from_bytes(b[14:15])
		return cls(interval_min, interval_max, advertising_type, own_address_type, direct_address_type, direct_address,
				   channel_map, filter_policy)


class SetAdvertisingData(CommandParameters):
	__slots__ = "data",
	MAX_LEN = 31
	Opcode = Opcode.from_ocf(LEControllerOpcode.SetAdvertisingData)

	def __init__(self, data: bytes) -> None:
		if len(data) > self.MAX_LEN:
			raise ValueError(f"max advertising data length {self.MAX_LEN} not {len(data)}")
		self.data = data

	def parameters_to_bytes(self) -> bytes:
		if not self.data:
			return U8(0).to_bytes()
		return U8(len(self.data)).to_bytes() + self.data

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'SetAdvertisingData':
		assert len(b) == b[0] + 1
		return cls(b[1:])


class AdvertisingEnable(CommandParameters):
	Opcode = Opcode.from_ocf(LEControllerOpcode.SetAdvertisingEnable)
	__slots__ = "enable",

	def __init__(self, enable: bool) -> None:
		self.enable = enable

	def parameters_to_bytes(self) -> bytes:
		return U8(self.enable).to_bytes()

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'AdvertisingEnable':
		assert b[0] == 0 or b[0] == 1
		return cls(b[0] == 1)

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
	__slots__ = "interval_min", "interval_max", "advertising_type", "own_address_type", "direct_address_type" \
		, "direct_address", "channel_map", "filter_policy"

	def __init__(self, interval_min: AdvertisingPeriod, interval_max: AdvertisingPeriod,
				 advertising_type: AdvertisingType,
				 own_address_type: AdvertisingType, direct_address_type: AdvertisingType, direct_address: DirectAddress,
				 channel_map: ChannelMap, filter_policy: FilterPolicy) -> None:
		self.interval_min = interval_min
		self.interval_max = interval_max
		self.advertising_type = advertising_type
		self.own_address_type = own_address_type
		self.direct_address_type = direct_address_type
		self.direct_address = direct_address
		self.channel_map = channel_map
		self.filter_policy = filter_policy



class SetAdvertisingData(CommandParameters):

import struct
from uuid import UUID
import datetime
import enum
from typing import *
from .mesh import *

class BeaconType(enum.IntEnum):
	UnprovisionedDevice = 0x00
	SecureNetwork = 0x01


beacon_classes = dict()  # type: Dict[BeaconType, type]


class Beacon:
	__slots__ = "beacon_type",

	def __init__(self, beacon_type: BeaconType):
		self.beacon_type = beacon_type

	def beacon_to_bytes(self) -> bytes:
		raise NotImplementedError()

	@classmethod
	def beacon_from_bytes(cls, b: bytes):
		raise NotImplementedError()

	def to_bytes(self):
		return self.beacon_type.to_bytes(1, byteorder='big') + self.beacon_to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Beacon':
		return beacon_classes[BeaconType(b[0])].beacon_from_bytes(b[1:])


class SecureBeaconAuthValue(U64):
	byteorder = "big"

class SecureBeacon(Beacon):
	__slots__ = "flags", "network_id", "iv_index", "authentication_value"
	def __init__(self, flags: NetworkStateFlags, network_id: NetworkID, iv_index: IVIndex, authentication_value: SecureBeaconAuthValue) -> None:
		super().__init__(BeaconType.SecureNetwork)
		self.flags = flags
		self.network_id = network_id
		self.iv_index = iv_index
		self.authentication_value = authentication_value

	def beacon_to_bytes(self) -> bytes:
		return self.flags.to_bytes(1, byteorder="big") + self.network_id.to_bytes() + self.iv_index.to_bytes() + self.authentication_value.to_bytes()

	@classmethod
	def beacon_from_bytes(cls, b: bytes) -> 'SecureBeacon':
		flags = NetworkStateFlags(b[0])
		network_id = NetworkID.from_bytes(b[1:5])
		iv_index = IVIndex.from_bytes(b[5:9])
		auth_value = SecureBeaconAuthValue.from_bytes(b[9:])
		return cls(flags, network_id, iv_index, auth_value)


class UnprovisionedBeacon(Beacon):
	STRUCT = struct.Struct("!16sH")
	__slots__ = "oob", "dev_uuid", "uri_hash", "last_seen"

	def __init__(self, oob: bytes, dev_uuid: UUID, uri_hash: bytes, last_seen: datetime.datetime):
		super().__init__(BeaconType.UnprovisionedDevice)
		self.oob = oob
		self.uri_hash = uri_hash
		self.dev_uuid = dev_uuid
		self.last_seen = last_seen

	@classmethod
	def beacon_from_bytes(cls, b: bytes) -> 'UnprovisionedBeacon':
		uuid_bytes, oob = cls.STRUCT.unpack(b[:cls.STRUCT.size])
		if len(b) > cls.STRUCT.size:
			uri_hash = b[cls.STRUCT.size:]
		else:
			uri_hash = None
		return cls(oob, UUID(bytes=uuid_bytes), uri_hash, datetime.datetime.now())

	def beacon_to_bytes(self) -> bytes:
		b = self.STRUCT.pack(self.dev_uuid.bytes, self.oob)
		if self.uri_hash:
			return b + self.uri_hash
		else:
			return b


beacon_classes[BeaconType.UnprovisionedDevice] = UnprovisionedBeacon
beacon_classes[BeaconType.SecureNetwork] = SecureBeacon

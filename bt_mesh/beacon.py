import struct
from uuid import UUID
import datetime
import enum
import time
from typing import *
from .mesh import *
from . import crypto


class BeaconType(enum.IntEnum):
	UnprovisionedDevice = 0x00
	SecureNetwork = 0x01


beacon_classes = dict()  # type: Dict[BeaconType, type]


class Beacon:
	__slots__ = "beacon_type", "rssi"

	def __init__(self, beacon_type: BeaconType, rssi: Optional[RSSI] = None):
		self.beacon_type = beacon_type
		self.rssi = rssi

	def beacon_to_bytes(self) -> bytes:
		raise NotImplementedError()

	@classmethod
	def beacon_from_bytes(cls, b: bytes):
		raise NotImplementedError()

	def to_bytes(self):
		return self.beacon_type.to_bytes(1, byteorder='big') + self.beacon_to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Beacon':
		return cast(Beacon, beacon_classes[BeaconType(b[0])]).beacon_from_bytes(b[1:])


class SecureBeaconAuthValue(U64):
	byteorder = "big"

	@classmethod
	def from_parts(cls, beacon_key: crypto.BeaconKey, flags: NetworkStateFlags, network_id: NetworkID,
				   iv_index: IVIndex) -> 'SecureBeaconAuthValue':
		return cls(crypto.aes_cmac(beacon_key,
								   flags.to_bytes(1, byteorder="big") + network_id.to_bytes() + iv_index.to_bytes())[
				   :8])


class SecureBeacon(Beacon):
	__slots__ = "flags", "network_id", "iv_index", "authentication_value"

	def __init__(self, flags: NetworkStateFlags, network_id: NetworkID, iv_index: IVIndex,
				 authentication_value: SecureBeaconAuthValue) -> None:
		super().__init__(BeaconType.SecureNetwork)
		self.flags = flags
		self.network_id = network_id
		self.iv_index = iv_index
		self.authentication_value = authentication_value

	def computed_auth(self, beacon_key: crypto.BeaconKey) -> SecureBeaconAuthValue:
		return SecureBeaconAuthValue.from_parts(beacon_key, self.flags, self.network_id, self.iv_index)

	def verify(self, beacon_key: crypto.BeaconKey) -> bool:
		return self.computed_auth(beacon_key) == self.authentication_value

	@classmethod
	def from_parts(cls, beacon_key: crypto.BeaconKey, flags: NetworkStateFlags, network_id: NetworkID,
				   iv_index: IVIndex) -> 'SecureBeacon':
		return cls(flags, network_id, iv_index,
				   SecureBeaconAuthValue.from_parts(beacon_key, flags, network_id, iv_index))

	def beacon_to_bytes(self) -> bytes:
		return self.flags.to_bytes(1,
								   byteorder="big") + self.network_id.to_bytes() + self.iv_index.to_bytes() + self.authentication_value.to_bytes()

	@classmethod
	def beacon_from_bytes(cls, b: bytes) -> 'SecureBeacon':
		flags = NetworkStateFlags(b[0])
		network_id = NetworkID.from_bytes(b[1:9])
		iv_index = IVIndex.from_bytes(b[9:13])
		auth_value = SecureBeaconAuthValue.from_bytes(b[13:])
		return cls(flags, network_id, iv_index, auth_value)


class SecureBeacons:
	def __init__(self) -> None:
		self.devices: Dict[NetKeyIndex, Tuple[SecureBeacon, datetime.datetime]] = dict()
		self.beacon_timeout = datetime.timedelta(minutes=1)
		self.on_good_beacon: Optional[Callable[[SecureBeacon, 'SecureBeacons'], None]] = None
		self.on_new_beacon: Optional[Callable[[SecureBeacon, 'SecureBeacons'], None]] = None

	def get_beacon_key(self, network_id: NetworkID) -> Optional[crypto.NetKeyIndex, crypto.BeaconKey]:
		pass

	def handle_beacon(self, incoming_beacon: SecureBeacon) -> None:
		seen_time = datetime.datetime.now()
		net_key_index, beacon_key = self.get_beacon_key(incoming_beacon.network_id)
		if beacon_key is None or net_key_index is None:
			# no beacon keys match network id
			return
		if not incoming_beacon.verify(beacon_key):
			# auth value doesn't match computed
			return
		new_beacon = False
		try:
			current_beacon, last_seen = self.devices[net_key_index]
			if seen_time < last_seen:
				# old beacon
				return
			if (last_seen + self.beacon_timeout) < seen_time:
				new_beacon = True
		except KeyError:
			# We haven't seen this network id yet
			pass

		self.devices[net_key_index] = incoming_beacon, seen_time
		if new_beacon:
			self.on_new_beacon(net_key_index, self)

		if self.on_good_beacon:
			self.on_good_beacon(net_key_index, self)


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

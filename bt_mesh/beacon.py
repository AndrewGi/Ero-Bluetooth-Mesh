from uuid import UUID
import datetime
from . import ble
import enum

class BeaconType(enum.IntEnum):
	UnprovisionedDevice = 0x00
	SecureNetwork = 0x01

class Beacon:
	pass

class SecureBeacon:
	pass

class UnprovisionedBeacon:
	__slots__ = "bt_address", "oob", "dev_uuid", "uri_hash", "last_seen"
	def __init__(self, bt_address: ble.BTAddress, oob: bytes, dev_uuid: UUID, uri_hash: bytes, last_seen: datetime.datetime):
		self.bt_address = bt_address
		self.oob = oob
		self.uri_hash = uri_hash
		self.dev_uuid = dev_uuid
		self.last_seen = last_seen

	@classmethod
	def from_bytes(cls, b: bytes, bt_address: ble.BTAddress, last_seen: datetime.datetime) -> 'UnprovisionedBeacon':
		if b[0] != BeaconType.UnprovisionedDevice:
			raise ValueError("unrecognized beacon message")
		if len(b)>18:
			uri_hash = b[19:]
		else:
			uri_hash = None
		return cls(bt_address, b[17:19], UUID(bytes=b[1:17]), uri_hash, last_seen)


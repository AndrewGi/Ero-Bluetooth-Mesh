from uuid import UUID
import datetime

class UnprovisionedBeacon:
	__slots__ = "bt_address", "oob", "dev_uuid", "last_seen"
	def __init__(self, bt_address: bytes, oob: bytes, dev_uuid: UUID, last_seen: datetime.datetime):
		if len(bt_address) != 6:
			raise ValueError("bt_address not 6 octects")
		self.bt_address = bt_address
		self.oob = oob
		self.dev_uuid = dev_uuid
		self.last_seen = last_seen

	@classmethod
	def from_bytes(cls, b: bytes, bt_address: bytes) -> 'UnprovisionedBeacon':
		return cls(bt_address, b[0:4], UUID(bytes=b[4:]))


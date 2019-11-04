import enum
from .. import serialize
from . import bt


class PDUType(serialize.U8, enum.Enum):
	ADV_IND = 0x00
	ADV_DIRECT_IND = 0x01
	ADV_NONCONN_IND = 0x02
	SCAN_REQ = 0x03
	SCAN_RSP = 0x04
	CONNECT_REQ = 0x05
	ADV_SCAN_IND = 0x06


class AdvData(serialize.ByteSerializable):
	MAX_LEN = 31
	__slots__ = "dat",

	def __init__(self, data: bytes) -> None:
		if len(data) > self.MAX_LEN:
			raise ValueError(f"len(data) {len(data)}>{self.MAX_LEN}")
		self.data = data

	def to_bytes(self) -> bytes:
		return self.data

	@classmethod
	def from_bytes(cls, b: bytes) -> 'AdvData':
		return cls(b)


class AdvPDU(serialize.ByteSerializable):
	__slots__ = "address", "data"

	def __init__(self, address: bt.Address, data: AdvData) -> None:
		self.address = address
		self.data = data

	def to_bytes(self) -> bytes:
		return self.address.to_bytes() + self.data.to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'AdvPDU':
		assert len(b) > 6, "6 bytes for adv_address + 0-31 for adv_data"
		return cls(bt.Address.from_bytes(b[:6]), AdvData.from_bytes(b[6:]))

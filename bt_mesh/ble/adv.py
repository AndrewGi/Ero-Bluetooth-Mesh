import datetime
import enum
from typing import *
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
	__slots__ = "data",

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
	__slots__ = "header", "address", "data"

	def __init__(self, address: bt.Address, data: AdvData) -> None:
		self.address = address
		self.data = data

	def to_bytes(self) -> bytes:
		return self.address.to_bytes() + self.data.to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'AdvPDU':
		assert len(b) > 6, "6 bytes for adv_address + 0-31 for adv_data"
		return cls(bt.Address.from_bytes(b[:6]), AdvData.from_bytes(b[6:]))


class AdvReceived(serialize.Serializable):
	__slots__ = "pdu", "rssi", "time_at"

	def __init__(self, pdu: AdvPDU, time_at: datetime.datetime, rssi: Optional[int] = None) -> None:
		self.pdu = pdu
		self.time_at = time_at
		self.rssi = rssi

	def to_dict(self) -> serialize.DictValue:
		out = {
			"pdu": serialize.base64_encode(self.pdu.to_bytes()),
			"time_at": self.time_at.strftime("%Y-%m-%d %H:%M:%S")
		}
		if self.rssi:
			out["rssi"] = self.rssi
		return out

	@classmethod
	def from_dict(cls, d: serialize.DictValue) -> 'AdvReceived':
		pdu = AdvPDU.from_bytes(serialize.base64_decode(d["pdu"]))
		time_at = datetime.datetime.strptime("%Y-%m-%d %H:%M:%S", d["time_at"])
		rssi = None if "rssi" not in d else int(d["rssi"])
		return cls(pdu, time_at, rssi)


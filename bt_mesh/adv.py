import enum
import struct

from . import bearer
class ADType(enum.IntEnum):
	MESH_BEACON = 0x2B
	MESH_MESSAGE = 0x2A
	MESH_PROVISION = 0x29
	MESH_URI = 0x24

class ADStructure:
	__slots__ = "ad_type", "data"
	def __init__(self, ad_type: ADType, data: bytes):
		self.ad_type = ad_type
		self.data = data

class PDUType(enum.IntEnum):
	ADV_IND = 0b000
	ADV_DIRECT_IND = 0b001
	ADV_NONCONN_IND = 0b010
	SCAN_REQ = 0b011
	SCAN_RSP = 0b100
	CONNECT_IND = 0b101
	ADV_SCAN_IND = 0b110

class AdvertisingHeader:
	__slots__ = "pdu_type", "ch_sel", "tx_add", "rx_add", "length"
	def __init__(self, pdu_type: PDUType, ch_sel: bool, tx_add: bool, rx_add: bool, length: int):
		self.pdu_type = pdu_type
		self.ch_sel = ch_sel
		self.tx_add = tx_add
		self.rx_add = rx_add
		self.length = length

	@classmethod
	def from_bytes(cls, b: bytes) -> 'AdvertisingHeader':
		assert len(b) == 2
		pdu_type = b[0] >> 4
		ch_sel = b[0] & 0x4 == 1
		tx_add = b[0] & 0x2 == 1
		rx_add = b[0] & 0x1 == 1
		length = b[1]
		return cls(PDUType(pdu_type), ch_sel, tx_add, rx_add, int(length))

	def to_bytes(self) -> bytes:
		return bytes([((self.pdu_type << 4) | (self.ch_sel << 2) | (self.tx_add << 1) | self.rx_add), self.length])

class PDU:
	def to_bytes(self) -> bytes:
		raise NotImplementedError()

	@classmethod
	def from_bytes(cls, b: bytes):
		raise NotImplementedError()

class AdvertisingPDU(PDU):

	MAX_PAYLOAD_LEN = 37
	__slots__ = "header", "payload"
	def __init__(self, header: ADType, payload: bytes):
		if len(payload) > self.MAX_PAYLOAD_LEN:
			raise ValueError("payload too big for one PDU")
		self.header = header
		self.payload = payload

	def to_bytes(self) -> bytes:
		return self.header.to_bytes() + self.payload

	@classmethod
	def from_bytes(cls, b: bytes) -> 'AdvertisingPDU':
		return cls(AdvertisingHeader(b[0:2]), b[2:])



class DataChannelPDU:
	MAX_PAYLOAD_LEN = 251
	__slots__ = "ad_type", "payload"
	def __init__(self, ad_type: ADType, payload: bytes):
		if len(payload) > self.MAX_PAYLOAD_LEN:
			raise ValueError("payload too big for one PDU")
		self.ad_type = ad_type
		self.payload = payload

class AdvertisementBearer(bearer.Bearer):
	pass
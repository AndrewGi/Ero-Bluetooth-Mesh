import enum
import struct
from typing import *
from uuid import UUID


class GPCF(enum.IntEnum):
	TRANSACTION_START = 0b00
	TRANSACTION_ACK = 0b01
	TRANSACTION_CONTINUE = 0b10
	PROVISIONING_BEARER_CONTROL = 0b11

class TransactionStartPDU:
	__slots__ = "seg_n", "data"
	def __init__(self, seg_n: int, fcs: int, data: bytes):
		self.seg_n = seg_n
		self.fcs = fcs
		self.data = data

	def length(self) -> int:
		return len(self.data)

	def fcs(self) -> int:
		raise NotImplementedError("IMPLEMENT crc8 HERE")

	def to_bytes(self) -> bytes:
		return struct.pack("!BHB", ((self.seg_n&0x3f)<<2)|GPCF.TRANSACTION_START, self.length(), self.fcs) + self.data

class TransactionAckPDU:
	@classmethod
	def to_bytes(cls) -> bytes:
		bytes([GPCF.TRANSACTION_ACK])

class TransactionContinuationPDU:
	__slots__ = "segment_index", "data"
	def __init__(self, segment_index: int, data: bytes):
		if (self.segment_index > 2**6)
			raise ValueError(f"segment_index too high {segment_index}")
		self.segment_index = segment_index
		self.data = data

	def to_bytes(self) -> byte:
		return bytes([(self.segment_index<<2) | GPCF.TRANSACTION_CONTINUE])

class BearerControlOpcode(enum.IntEnum):
	LinkOpen = 0x00
	LinkACK = 0x01
	LinkClose = 0x02


class ProvisioningBearerControlPDU:
	__slots__ = "opcode", "parameters"
	def __init__(self, opcode: BearerControlOpcode, parameters: bytes):
		self.opcode = opcode
		self.parameters = parameters

	def to_bytes(self) -> bytes:
		return bytes([(self.opcode<<2)|GPCF.PROVISIONING_BEARER_CONTROL])


class LinkOpenMessage:
	__slots__ = "dev_uuid",

	def __init__(self, dev_uuid: UUID):
		self.dev_uuid = dev_uuid

	def to_pdu(self) -> ProvisioningBearerControlPDU:
		return ProvisioningBearerControlPDU(BearerControlOpcode.LinkOpen, self.dev_uuid.bytes)

	@classmethod
	def from_pdu(cls, pdu: ProvisioningBearerControlPDU) -> 'LinkOpenMessage':
		if pdu.opcode != BearerControlOpcode.LinkOpen:
			raise ValueError(f"opcode not link_open {pdu.opcode}")
		if len(pdu.parameters)!=16:
			raise ValueError("dev uuid wrong length")
		return cls(UUID(bytes=pdu.parameters))

class LinkAckMessage:

	@classmethod
	def to_pdu(cls) -> ProvisioningBearerControlPDU:
		return ProvisioningBearerControlPDU(BearerControlOpcode.LinkACK, bytes())

class LinkCloseReason(enum.IntEnum):
	Success = 0
	Timeout = 1
	Fail = 2

class LinkCloseMessage:
	__slots__ = "reason",
	def __init__(self, reason: LinkCloseMessage):
		self.reason = reason

	def to_pdu(self) -> ProvisioningBearerControlPDU:
		return ProvisioningBearerControlPDU(BearerControlOpcode.LinkClose, self.reason.to_bytes(1, byteorder="big"))
	@classmethod
	def from_pdu(cls, pdu: ProvisioningBearerControlPDU) -> 'LinkCloseMessage':
		if pdu.opcode != BearerControlOpcode.LinkClose:
			raise ValueError(f"opcode not link_close {pdu.opcode}")
		if len(pdu.parameters)!=1:
			raise ValueError("reason wrong length")
		return cls(LinkCloseMessage(pdu.parameters[0]))

class GenericProvisionControl:
	MAX_LEN = 17
	pass

class GenericProvisionPayload:
	MAX_LEN = 64

class GenericProvisioningPDU:
	MAX_LEN = 24
	def __init__(self):
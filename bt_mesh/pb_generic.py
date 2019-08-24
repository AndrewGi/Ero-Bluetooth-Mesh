import enum
import struct
from typing import *
from uuid import UUID

crc8_table = [
	0x00, 0x91, 0xe3, 0x72, 0x07, 0x96, 0xe4, 0x75,
	0x0e, 0x9f, 0xed, 0x7c, 0x09, 0x98, 0xea, 0x7b,
	0x1c, 0x8d, 0xff, 0x6e, 0x1b, 0x8a, 0xf8, 0x69,
	0x12, 0x83, 0xf1, 0x60, 0x15, 0x84, 0xf6, 0x67,

	0x38, 0xa9, 0xdb, 0x4a, 0x3f, 0xae, 0xdc, 0x4d,
	0x36, 0xa7, 0xd5, 0x44, 0x31, 0xa0, 0xd2, 0x43,
	0x24, 0xb5, 0xc7, 0x56, 0x23, 0xb2, 0xc0, 0x51,
	0x2a, 0xbb, 0xc9, 0x58, 0x2d, 0xbc, 0xce, 0x5f,

	0x70, 0xe1, 0x93, 0x02, 0x77, 0xe6, 0x94, 0x05,
	0x7e, 0xef, 0x9d, 0x0c, 0x79, 0xe8, 0x9a, 0x0b,
	0x6c, 0xfd, 0x8f, 0x1e, 0x6b, 0xfa, 0x88, 0x19,
	0x62, 0xf3, 0x81, 0x10, 0x65, 0xf4, 0x86, 0x17,

	0x48, 0xd9, 0xab, 0x3a, 0x4f, 0xde, 0xac, 0x3d,
	0x46, 0xd7, 0xa5, 0x34, 0x41, 0xd0, 0xa2, 0x33,
	0x54, 0xc5, 0xb7, 0x26, 0x53, 0xc2, 0xb0, 0x21,
	0x5a, 0xcb, 0xb9, 0x28, 0x5d, 0xcc, 0xbe, 0x2f,

	0xe0, 0x71, 0x03, 0x92, 0xe7, 0x76, 0x04, 0x95,
	0xee, 0x7f, 0x0d, 0x9c, 0xe9, 0x78, 0x0a, 0x9b,
	0xfc, 0x6d, 0x1f, 0x8e, 0xfb, 0x6a, 0x18, 0x89,
	0xf2, 0x63, 0x11, 0x80, 0xf5, 0x64, 0x16, 0x87,

	0xd8, 0x49, 0x3b, 0xaa, 0xdf, 0x4e, 0x3c, 0xad,
	0xd6, 0x47, 0x35, 0xa4, 0xd1, 0x40, 0x32, 0xa3,
	0xc4, 0x55, 0x27, 0xb6, 0xc3, 0x52, 0x20, 0xb1,
	0xca, 0x5b, 0x29, 0xb8, 0xcd, 0x5c, 0x2e, 0xbf,

	0x90, 0x01, 0x73, 0xe2, 0x97, 0x06, 0x74, 0xe5,
	0x9e, 0x0f, 0x7d, 0xec, 0x99, 0x08, 0x7a, 0xeb,
	0x8c, 0x1d, 0x6f, 0xfe, 0x8b, 0x1a, 0x68, 0xf9,
	0x82, 0x13, 0x61, 0xf0, 0x85, 0x14, 0x66, 0xf7,

	0xa8, 0x39, 0x4b, 0xda, 0xaf, 0x3e, 0x4c, 0xdd,
	0xa6, 0x37, 0x45, 0xd4, 0xa1, 0x30, 0x42, 0xd3,
	0xb4, 0x25, 0x57, 0xc6, 0xb3, 0x22, 0x50, 0xc1,
	0xba, 0x2b, 0x59, 0xc8, 0xbd, 0x2c, 0x5e, 0xcf
]


def fcs_calc(data: bytes) -> int:
	fcs = 0xFF
	for b in data:
		fcs = crc8_table[fcs ^ b]
	return 0xFF - fcs


def fcs_check(fcs: int, data: bytes) -> bool:
	fcs_check = 0xFF
	for b in data:
		fcs_check = crc8_table[fcs_check ^ b]
	return crc8_table[fcs_check ^ fcs] == 0xCF


class GPCF(enum.IntEnum):
	TRANSACTION_START = 0b00
	TRANSACTION_ACK = 0b01
	TRANSACTION_CONTINUE = 0b10
	PROVISIONING_BEARER_CONTROL = 0b11


GPCF_classes = dict()  # type: Dict[GPCF, Any]


class GenericProvisioningPDU:
	MAX_LEN = 24

	def __init__(self):
		self.transaction_number = None

	def payload(self) -> bytes:
		return bytes()

	def control_to_bytes(self) -> bytes:
		raise NotImplementedError()

	@classmethod
	def control_pdu_size(cls) -> int:
		raise NotImplementedError()

	def to_bytes(self) -> bytes:
		return self.control_to_bytes() + self.payload()

	@staticmethod
	def gpcf() -> GPCF:
		raise NotImplementedError()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'GenericProvisioningPDU':
		gpcf = GPCF(b[0] & 0x03)
		gpcf_cls = GPCF_classes[gpcf]
		control_bytes = b[:gpcf_cls.control_pdu_size()]
		payload = b[gpcf_cls.control_pdu_size():]
		out = gpcf_cls.control_from_bytes(control_bytes)
		if payload:
			out.set_payload(payload)
		return out


class TransactionStartPDU(GenericProvisioningPDU):
	__slots__ = "seg_n", "length", "fcs", "data"

	def __init__(self, seg_n: int, length: int, fcs: int = None, data: bytes = None):
		super().__init__()
		if data is not None and fcs is None:
			self.fcs = fcs_calc(data)
		else:
			self.fcs = fcs
		self.data = data
		self.seg_n = seg_n
		self.length = length

	def payload(self) -> bytes:
		return self.data

	def set_payload(self, payload: bytes, check_fcs: bool = True, set_fcs: bool = False):
		if check_fcs:
			if not fcs_check(self.fcs, payload):
				raise ValueError("invalid fcs")
		elif set_fcs:
			self.fcs = fcs_calc(payload)
		self.data = payload

	@classmethod
	def control_pdu_size(cls) -> int:
		return 4

	def control_to_bytes(self) -> bytes:
		return struct.pack("!BHB", ((self.seg_n & 0x3f) << 2) | GPCF.TRANSACTION_START, self.length, self.fcs)

	@classmethod
	def control_from_bytes(cls, b: bytes):
		seg_n, length, fcs = struct.unpack("!BHB", b)
		seg_n = ((seg_n & 0xFC) >> 2)
		return cls(seg_n, length, fcs)

	@staticmethod
	def gpcf() -> GPCF:
		return GPCF.TRANSACTION_START


class TransactionAckPDU(GenericProvisioningPDU):

	def __init__(self, transaction_number: int = None):
		self.transaction_number = transaction_number

	@classmethod
	def control_pdu_size(cls) -> int:
		return 1

	@classmethod
	def control_to_bytes(cls) -> bytes:
		return bytes([GPCF.TRANSACTION_ACK])

	@classmethod
	def control_from_bytes(cls, b: bytes):
		return cls()

	@staticmethod
	def gpcf() -> GPCF:
		return GPCF.TRANSACTION_ACK


class TransactionContinuationPDU(GenericProvisioningPDU):
	LEN = 1
	__slots__ = "segment_index", "segment_data"

	def __init__(self, segment_index: int, segment_data: bytes):
		super().__init__()
		if self.segment_index > 2 ** 6:
			raise ValueError(f"segment_index too high {segment_index}")
		self.segment_data = segment_data
		self.segment_index = segment_index

	def payload(self) -> bytes:
		return self.segment_data

	def control_to_bytes(self) -> bytes:
		return bytes([(self.segment_index << 2) | GPCF.TRANSACTION_CONTINUE])

	@classmethod
	def control_from_bytes(cls, b: bytes) -> 'TransactionContinuationPDU':
		return cls(b[0] << 2, b[1:])

	@classmethod
	def control_pdu_size(cls) -> int:
		return 2

	@staticmethod
	def gpcf() -> GPCF:
		return GPCF.TRANSACTION_CONTINUE


class BearerControlOpcode(enum.IntEnum):
	LinkOpen = 0x00
	LinkACK = 0x01
	LinkClose = 0x02


bearer_control_opcode_classes = dict()  # type: Dict[BearerControlOpcode, Any]


class BearerControlPDU(GenericProvisioningPDU):
	LEN = 1
	__slots__ = "opcode"

	def __init__(self, opcode: BearerControlOpcode):
		super().__init__()
		self.opcode = opcode

	def control_to_bytes(self) -> bytes:
		return bytes([(self.opcode >> 2) | GPCF.PROVISIONING_BEARER_CONTROL]) + self.bearer_to_bytes()

	@classmethod
	def control_pdu_size(cls) -> int:
		return 1

	def bearer_to_bytes(self) -> bytes:
		raise NotImplementedError()

	@classmethod
	def bearer_from_bytes(cls, b: bytes) -> bytes:
		raise NotImplementedError()

	@classmethod
	def control_from_bytes(cls, b: bytes) -> 'BearerControlPDU':
		opcode = BearerControlOpcode(b[0] >> 2)
		return bearer_control_opcode_classes[opcode].bearer_from_bytes(b[1:])

	@staticmethod
	def gpcf() -> GPCF:
		return GPCF.PROVISIONING_BEARER_CONTROL


class LinkOpenMessage(BearerControlPDU):
	LEN = 16
	__slots__ = "dev_uuid",

	def __init__(self, dev_uuid: UUID):
		super().__init__(BearerControlOpcode.LinkOpen)
		self.dev_uuid = dev_uuid

	@classmethod
	def bearer_from_bytes(cls, b: bytes) -> 'LinkOpenMessage':
		return cls(UUID(bytes=b))

	def bearer_to_bytes(self) -> bytes:
		return self.dev_uuid.bytes


class LinkAckMessage(BearerControlPDU):

	def __init__(self):
		super().__init__(BearerControlOpcode.LinkACK)

	@classmethod
	def bearer_from_bytes(cls, b: bytes) -> 'LinkAckMessage':
		if len(b) != 0:
			raise ValueError("ack message not empty")
		return cls()

	def bearer_to_bytes(self) -> bytes:
		return bytes()


class LinkCloseReason(enum.IntEnum):
	Success = 0
	Timeout = 1
	Fail = 2


class LinkCloseMessage(BearerControlPDU):
	__slots__ = "reason",

	def __init__(self, reason: LinkCloseReason):
		super().__init__(BearerControlOpcode.LinkClose)
		self.reason = reason

	@classmethod
	def bearer_from_bytes(cls, b: bytes) -> 'LinkCloseMessage':
		return cls(LinkCloseReason(b[0]))

	def bearer_to_bytes(self) -> bytes:
		return bytes([self.reason])


GPCF_classes[GPCF.TRANSACTION_START] = TransactionStartPDU
GPCF_classes[GPCF.TRANSACTION_ACK] = TransactionAckPDU
GPCF_classes[GPCF.TRANSACTION_CONTINUE] = TransactionContinuationPDU
GPCF_classes[GPCF.PROVISIONING_BEARER_CONTROL] = BearerControlPDU

bearer_control_opcode_classes[BearerControlOpcode.LinkACK] = LinkAckMessage
bearer_control_opcode_classes[BearerControlOpcode.LinkOpen] = LinkOpenMessage
bearer_control_opcode_classes[BearerControlOpcode.LinkClose] = LinkCloseMessage

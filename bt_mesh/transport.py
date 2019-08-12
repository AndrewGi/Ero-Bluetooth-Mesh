import struct

from .mesh import *
from . import crypto, security
import enum


class CTLOpcode(enum.IntEnum):
	ACK = 0x00
	FRIEND_POLL = 0x01
	FRIEND_UPDATE = 0x02
	FRIEND_REQ = 0x03
	FRIEND_OFFER = 0x04
	FRIEND_CLEAR = 0x05
	FRIEND_CLEAR_CFM = 0x06
	FRIEND_SUB_ADD = 0x07
	FRIEND_SUB_REM = 0x08
	FRIEND_SUB_CFM = 0x09
	HEARTBEAT = 0x0A


class UpperEncryptedAccessPDU:
	__slots__ = "data", "mic", "aid",

	def __init__(self, aid: AID, data: bytes, mic: MIC):
		self.aid = aid
		self.data = data
		self.mic = mic

	def akf(self) -> bool:
		return self.aid is not None

	def to_bytes(self) -> bytes:
		return self.data + self.mic.bytes_be

	@classmethod
	def from_bytes(cls, b: bytes, big_mic: bool, aid: Optional[AID] = None) -> 'UpperEncryptedAccessPDU':
		mic_size = 8 if big_mic else 4
		mic = MIC(b[mic_size:])
		return cls(aid, b[:mic_size], mic)


class UpperAccessPDU:
	__slots__ = "payload", "big_mic"

	def __init__(self, payload: bytes, big_mic: Optional[bool] = False):
		self.payload = payload
		self.big_mic = big_mic

	@overload
	def encrypt(self, sm: crypto.DeviceSecurityMaterial) -> UpperEncryptedAccessPDU:
		...

	@overload
	def encrypt(self, sm: crypto.AppSecurityMaterial,
				virtual_address: Optional[VirtualAddress] = None) -> UpperEncryptedAccessPDU:
		...

	def encrypt(self, sm: crypto.TransportSecurityMaterial,
				virtual_address: Optional[VirtualAddress] = None) -> UpperEncryptedAccessPDU:
		data, mic = sm.transport_encrypt(self.payload, self.big_mic, virtual_address)
		is_app = isinstance(sm, crypto.AppSecurityMaterial)
		aid = cast(crypto.AppSecurityMaterial, sm).aid() if is_app else None
		return UpperEncryptedAccessPDU(aid, data, mic)

	@classmethod
	@overload
	def decrypt(cls, b: bytes, mic: MIC, sm: crypto.DeviceSecurityMaterial) -> 'UpperAccessPDU':
		...

	@classmethod
	@overload
	def decrypt(cls, b: bytes, mic: MIC, sm: crypto.AppSecurityMaterial,
				virtual_address: Optional[VirtualAddress] = None) -> 'UpperAccessPDU':
		...

	@classmethod
	def decrypt(cls, b: bytes, mic: MIC, sm: crypto.TransportSecurityMaterial,
				virtual_address: Optional[VirtualAddress] = None) -> 'UpperAccessPDU':
		return cls(sm.transport_decrypt(b, mic, virtual_address), mic.mic_len() == 64)


class LowerPDU:

	def to_bytes(self) -> bytes:
		raise NotImplementedError()

	@classmethod
	def from_bytes(cls, b: bytes):
		raise NotImplementedError()


def make_seq_zero(head_flag: bool, seq_zero: int, seg_o: int, seg_n: int) -> bytes:
	return bytes([(head_flag << 7) | ((seq_zero & 0x07E0) >> 6)
					 , ((seq_zero & 0x3F) << 2) | ((seg_o & 0x18) >> 3)
					 , ((seg_o & 0x07) << 5) | seg_n & 0x3F])


def extract_seq_zero(b: bytes) -> Tuple[bool, int, int, int]:
	# TODO: Check these functions
	head_flag = (b[0] & 0x80) == 0x80
	seq_zero = (b[0] & 0x3F) << 6
	seq_zero |= (b[1] & 0xFC) >> 2
	seg_o = (b[1] & 0x03) >> 3
	seg_o |= (b[2] & 0xE0) << 5
	seg_n = b[2] & 0x3F
	return head_flag, seq_zero, seg_o, seg_n


class UnsegmentedAccessLowerPDU(LowerPDU):
	__slots__ = "afk", "aid", "upper_pdu"

	def __init__(self, afk: bool, aid: AID, upper_pdu: bytes):
		self.afk = afk
		self.aid = aid
		self.upper_pdu = upper_pdu

	def to_bytes(self) -> bytes:
		return bytes([(self.afk << 6) | self.aid]) + self.upper_pdu

	@classmethod
	def from_bytes(cls, b: bytes) -> 'UnsegmentedAccessLowerPDU':
		afk = b[0] & 0x4 == 0x4
		aid = AID(b[0] & 0x3F)
		upper_pdu = b[1:]
		return cls(afk, aid, upper_pdu)


class SegmentedAccessLowerPDU(LowerPDU):
	SEG_LEN = 12
	STRUCT = struct.Struct("!B3s")
	__slots__ = ("afk", "aid", "szmic", "seq_zero", "seg_o", "seq_n", "segment")

	def __init__(self, afk: bool, szmic: bool, aid: AID, seq_zero: int, seg_o: int, seg_n: int, segment: bytes):
		self.afk = afk
		self.aid = aid
		self.seq_zero = seq_zero
		self.seg_o = seg_o
		self.seg_n = seg_n
		self.segment = segment
		self.szmic = szmic

	def to_bytes(self) -> bytes:
		seq = make_seq_zero(self.szmic, self.seq_zero, self.seg_o, self.seg_n)
		return self.STRUCT.pack(0x80 | (self.afk << 6) | (self.aid & 0x3f), seq)

	@classmethod
	def from_bytes(cls, b: bytes) -> 'SegmentedAccessLowerPDU':
		afk = b[0] & 0x4 == 0x4
		aid = AID(b[0] & 0x3F)
		szmic, seq_zero, seg_o, seg_n = extract_seq_zero(b[1:3])
		segment = b[3:]
		return cls(afk, szmic, aid, seq_zero, seg_o, seg_n, segment)


class UnsegmentedControlLowerPDU(LowerPDU):
	MAX_PARAMETERS_LEN = 88
	__slots__ = "opcode", "parameters"

	def __init__(self, opcode: CTLOpcode, parameters: bytes):
		if len(parameters) > self.MAX_PARAMETERS_LEN:
			raise ValueError(f"parameters too long: {len(parameters)}>{self.MAX_PARAMETERS_LEN}")
		self.parameters = parameters
		self.opcode = opcode

	def to_bytes(self) -> bytes:
		return bytes([self.opcode & 0x3f]) + self.parameters

	@classmethod
	def from_bytes(cls, b: bytes) -> 'UnsegmentedControlLowerPDU':
		return cls(opcode=CTLOpcode(b[0] & 0x3f), parameters=b[1:])


class SegmentedControlLowerPDU(LowerPDU):
	SEG_LEN = 8
	__slots__ = "opcode", "obo", "seq_zero", "seg_o", "seg_n", "segment"

	def __init__(self, opcode: CTLOpcode, obo: bool, seq_zero: int, seg_o: int, seg_n: int, segment: bytes):
		self.opcode = opcode
		self.obo = obo
		self.seq_zero = seq_zero
		self.seg_o = seg_o
		self.seg_n = seg_n
		self.segment = segment

	def to_bytes(self) -> bytes:
		return bytes([0x80 | self.opcode]) + make_seq_zero(False, self.seq_zero, self.seg_o, self.seg_n) + self.segment

	@classmethod
	def from_bytes(cls, b: bytes):
		pass

	def is_start(self) -> bool:
		return self.seg_n == 1

	def is_end(self) -> bool:
		return self.seg_n == self.seg_o


class SegmentAcknowledgementLowerPDU(LowerPDU):
	__slots__ = "obo", "seq_zero", "block_ack"

	def __init__(self, obo: bool, seq_zero: int, block_ack: int):
		self.obo = obo
		self.seq = seq_zero
		self.block_ack = block_ack

	def to_bytes(self) -> bytes:
		return bytes([0]) + make_seq_zero(self.obo, self.seq_zero, 0, 0)[0:2] + self.block_ack

	@classmethod
	def from_bytes(cls, b: bytes) -> 'SegmentAcknowledgementLowerPDU':
		if b[0] != 0x00:
			raise ValueError("PDU not a segment acknowledgement lower pdu")
		seq_zero_obo = int.from_bytes(b[1:3], byteorder="big")
		return cls(obo=(seq_zero_obo & 0x7000) == 0x7000, seq_zero=(seq_zero_obo >> 2) & 0x1FFF, block_ack=b[3:3 + 4])


class SegmentAssembler:

	def __init__(self, first_pdu: LowerPDU):
		if isinstance(first_pdu, SegmentedControlLowerPDU):
			self.ctl = True
		elif isinstance(first_pdu, SegmentedAccessLowerPDU):
			self.ctl = False
		else:
			raise ValueError("unexpected lower pdu type")
		pdu = self.verify(first_pdu)
		self.szmic = pdu.szmic
		self.seg_n = first_pdu.seg_n
		self.seg_mask = (2 ** self.seg_n) - 1
		self.segs_needed = self.seg_mask
		self.seg_len = pdu.SEG_LEN
		self.known_len = 0
		self.max_len = self.seg_n * self.seg_len
		self.data = bytearray(self.max_len)

	def verify(self, pdu: LowerPDU) -> Union[SegmentedAccessLowerPDU, SegmentedControlLowerPDU]:
		if self.ctl and isinstance(pdu, SegmentedControlLowerPDU):
			return cast(SegmentedControlLowerPDU, pdu)
		elif not self.ctl and isinstance(pdu, SegmentedAccessLowerPDU):
			return cast(SegmentedAccessLowerPDU, pdu)
		else:
			raise ValueError(f"unexpected lower pdu type ctl:{self.ctl} pdu:{pdu}")

	def insert_segment(self, seg_i: int, position: int, data: bytes):
		if position + len(data) > self.max_len:
			raise ValueError("data out of bounds")
		if seg_i != self.seg_n:
			if len(data) != self.seg_len:
				raise ValueError(f"incorrect segment length. expect {self.seg_len} got {len(data)}")
		else:
			# last packet
			self.known_len = position + len(data)
		for i in range(len(data)):
			self.data[i + position] = data[i]
		self.segs_needed = self.segs_needed & (~(1 << seg_i) & self.seg_mask)

	def insert_ctl(self, pdu: SegmentedControlLowerPDU):
		assert self.ctl, "trying to insert a control pdu into an access segment assembly"
		position = pdu.seg_n * pdu.SEG_LEN
		self.insert_segment(pdu.seg_o, position, pdu.segment)

	def insert_access(self, pdu: SegmentedAccessLowerPDU):
		assert not self.ctl, "trying to insert a access pdu into a ctl segment assembly"
		position = pdu.seg_n * pdu.SEG_LEN
		self.insert_segment(pdu.seg_o, position, pdu.segment)

	def upper_bytes(self) -> bytes:
		assert self.is_done() and self.known_len, "segment assemble must be done before getting upper transport pdu"
		return self.data[:self.known_len]

	def is_done(self) -> bool:
		return self.segs_needed == 0

	def get_upper(self) -> Union[UpperEncryptedAccessPDU]:
		if self.ctl:
			raise NotImplementedError()
		else:
			return UpperEncryptedAccessPDU.from_bytes(self.upper_bytes(), self.szmic)

	def insert(self, pdu: LowerPDU):
		pdu = self.verify(pdu)
		if self.ctl:
			self.insert_ctl(pdu)
		else:
			self.insert_access(pdu)


def make_lower_pdu(raw_bytes: bytes, ctl: bool):
	if (raw_bytes[0] & 0x80) == 1:
		if ctl:
			if raw_bytes[0] == 0x80:
				return SegmentedAccessLowerPDU.from_bytes(raw_bytes)
			else:
				return SegmentedControlLowerPDU.from_bytes(raw_bytes)
	else:
		if ctl:
			return UnsegmentedControlLowerPDU.from_bytes(raw_bytes)
		else:
			return UnsegmentedAccessLowerPDU.from_bytes(raw_bytes)

import struct

from .mesh import *
from . import crypto
import enum


class ApplicationPayload:
	def to_bytes(self) -> bytes:
		pass


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


class EncryptedUpperPDU:
	__slots__ = "encrypted_app_payload", "trans_mic"


class UpperAccessPDU:
	__slots__ = "app_payload",

	def __init__(self, app_payload: ApplicationPayload):
		self.app_payload = app_payload

	def encrypt_app(self, app_key: crypto.Appkey, nonce: crypto.ApplicationNonce,
					virtual_address: Optional[VirtualAddress] = None) -> Tuple[bytes, MIC]:
		a = virtual_address.uuid.bytes if virtual_address else bytes()
		return crypto.aes_ccm_encrypt(app_key, nonce, self.app_payload.to_bytes(), a)

	def encrypt_dev(self, dev_key: crypto.DeviceKey, nonce: crypto.DeviceNonce) -> Tuple[bytes, MIC]:
		return crypto.aes_ccm_encrypt(dev_key, nonce, self.app_payload.to_bytes())

	@classmethod
	def decrypt_add(self, b: bytes, app_key: crypto.Appkey, nonce: crypto.ApplicationNonce,
					virtual_address: Optional[VirtualAddress] = None) -> 'UpperPDU':
		pass


class LowerPDU:

	def to_bytes(self) -> bytes:
		raise NotImplementedError()

	def from_bytes(cls, b: bytes):
		raise NotImplementedError()


def make_seq_zero(head_flag: bool, seq_zero: int, seg_o: int, seg_n: int) -> bytes:
	return bytes([(head_flag << 7) | ((seq_zero & 0x07E0) >> 6)
		, ((seq_zero & 0x3F) << 2) | ((seg_o & 0x18) >> 3)
		, ((seg_o & 0x07) << 5) | seg_n & 0x3F])

def extract_seq_zero(b: bytes) -> Tuple[bool, int, int, int]:
	#TODO: Check these functions
	head_flag = (b[0]&0x80)==0x80
	seq_zero = (b[0]&0x3F) << 6
	seq_zero |= (b[1]&0xFC) >> 2
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
		afk = b[0]&0x4 == 0x4
		aid = AID(b[0]&0x3F)
		upper_pdu = b[1:]
		return cls(afk, aid, upper_pdu)



class SegmentedAccessLowerPDU(LowerPDU):
	STRUCT = struct.Struct("!B3s")
	__slots__ = ("afk", "aid", "szmic", "seq_zero", "seg_o", "seq_n", "segment")

	def __init__(self, afk: bool, aid: AID, seq_zero: int, seg_o: int, seg_n: int, segment: bytes):
		self.afk = afk
		self.aid = aid
		self.seq_zero = seq_zero
		self.seg_o = seg_o
		self.seg_n = seg_n
		self.segment = segment

	def to_bytes(self) -> bytes:
		seq = make_seq_zero(self.szmic, self.seq_zero, self.seg_o, self.seg_n)
		return self.STRUCT.pack(0x80 | (self.afk << 6) | (self.aid & 0x3f), seq)

	@classmethod
	def from_bytes(cls, b: bytes) -> 'SegmentedAccessLowerPDU':
		afk = b[0]&0x4 == 0x4
		aid = AID(b[0]&0x3F)
		szmic, seq_zero, seg_o, seg_n = extract_seq_zero(b[1:3])
		segment = b[3:]
		return cls(afk, aid, seq_zero, seg_o, seg_n, segment)


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
		self.last_seg = first_pdu.seg_n

	def verify(self, pdu: LowerPDU):
		if (self.ctl and isinstance(pdu, SegmentedControlLowerPDU)) or \
				(not self.ctl and isinstance(pdu, SegmentedAccessLowerPDU)):
			return
		else:
			raise ValueError("unexpected lower pdu type")
	def insert(self, pdu: LowerPDU):
		self.verify(pdu)



def make_lower_pdu(raw_bytes: bytes, ctl: bool):
	if (raw_bytes[0]&0x80)==1:
		if ctl:
			if raw_bytes[0] == 0x80:
				return SegmentAcknowledgementLowerPDU.from_bytes(raw_bytes)
			else:
				return SegmentedControlLowerPDU.from_bytes(raw_bytes)
	else:
		if ctl:
			return UnsegmentedControlLowerPDU.from_bytes(raw_bytes)
		else:
			return UnsegmentedAccessLowerPDU.from_bytes(raw_bytes)


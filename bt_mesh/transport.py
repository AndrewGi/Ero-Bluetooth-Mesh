import struct
import time

from .mesh import *
from . import crypto
import enum
import heapq
import threading


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

	def __len__(self) -> int:
		return len(self.data) + len(self.mic)

	def akf(self) -> bool:
		return self.aid is not None

	def to_bytes(self) -> bytes:
		return self.data + self.mic.bytes_be

	@classmethod
	def from_bytes(cls, b: bytes, big_mic: bool, aid: Optional[AID] = None) -> 'UpperEncryptedAccessPDU':
		mic_size = 8 if big_mic else 4
		mic = MIC(b[mic_size:])
		return cls(aid, b[:mic_size], mic)

	@overload
	def decrypt(self, nonce: crypto.DeviceNonce, sm: crypto.DeviceSecurityMaterial) -> 'UpperAccessPDU':
		...

	@overload
	def decrypt(self, nonce: crypto.ApplicationNonce, sm: crypto.AppSecurityMaterial,
				virtual_address: Optional[VirtualAddress] = None) -> 'UpperAccessPDU':
		...

	def decrypt(self, nonce: crypto.Nonce, sm: crypto.TransportSecurityMaterial,
				virtual_address: Optional[VirtualAddress] = None) -> 'UpperAccessPDU':
		return UpperAccessPDU(sm.transport_decrypt(nonce, self.data, self.mic, virtual_address),
							  self.mic.mic_len() == 64)

	def should_segment(self) -> bool:
		return len(self) <= UnsegmentedAccessLowerPDU.MAX_UPPER_LEN

	def unsegmented(self) -> 'UnsegmentedAccessLowerPDU':
		if self.should_segment():
			raise OverflowError(
				f"max unsegmented size is {UnsegmentedAccessLowerPDU.MAX_UPPER_LEN} but message size is {len(self)}")
		return UnsegmentedAccessLowerPDU(self.aid is not None, self.aid, crypto.data_and_mic_bytes(self.data, self.mic))

	def seg_n(self) -> int:
		seg_size = SegmentedAccessLowerPDU.SEG_LEN
		return (len(self) // seg_size) + ((len(self) % seg_size) != 0)

	def segmented(self, start_seq: Seq) -> Generator['SegmentedAccessLowerPDU', None, None]:
		seq_zero = start_seq
		seg_size = SegmentedAccessLowerPDU.SEG_LEN
		seg_n = self.seg_n()
		seg_o = 0
		total_data = self.to_bytes()
		big_mic = self.mic.mic_len() == 64
		while seg_o < seg_n:
			data = total_data[seg_o * seg_size:(seg_o + 1) * seg_size]
			yield SegmentedAccessLowerPDU(self.akf(), big_mic, self.aid, seq_zero, seg_o, seg_n, data)
		yield SegmentedAccessLowerPDU(self.akf(), big_mic, self.aid, seq_zero, seg_o, seg_n,
									  total_data[seg_o * seg_size:])


class UpperAccessPDU:
	__slots__ = "payload", "big_mic"

	def __init__(self, payload: bytes, big_mic: Optional[bool] = False):
		self.payload = payload
		self.big_mic = big_mic

	@overload
	def encrypt(self, nonce: crypto.DeviceNonce, sm: crypto.DeviceSecurityMaterial) -> UpperEncryptedAccessPDU:
		...

	@overload
	def encrypt(self, nonce: crypto.ApplicationNonce, sm: crypto.AppSecurityMaterial,
				virtual_address: Optional[VirtualAddress] = None) -> UpperEncryptedAccessPDU:
		...

	def encrypt(self, nonce: crypto.Nonce, sm: crypto.TransportSecurityMaterial,
				virtual_address: Optional[VirtualAddress] = None) -> UpperEncryptedAccessPDU:
		is_app = isinstance(sm, crypto.AppSecurityMaterial)
		aid = cast(crypto.AppSecurityMaterial, sm).aid() if is_app else None
		data, mic = sm.transport_encrypt(nonce, self.payload, self.big_mic, virtual_address)
		return UpperEncryptedAccessPDU(aid, data, mic)


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
	MAX_UPPER_LEN = 15
	__slots__ = "afk", "aid", "upper_pdu"

	def __init__(self, afk: bool, aid: AID, upper_pdu: UpperEncryptedAccessPDU):
		if len(upper_pdu) > self.MAX_UPPER_LEN:
			raise ValueError(f"upper_pdu max {self.MAX_UPPER_LEN} bytes but given {len(upper_pdu)}")
		self.afk = afk
		self.aid = aid
		self.upper_pdu = upper_pdu

	def to_bytes(self) -> bytes:
		return bytes([(self.afk << 6) | self.aid]) + self.upper_pdu.to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'UnsegmentedAccessLowerPDU':
		afk = b[0] & 0x4 == 0x4
		aid = AID(b[0] & 0x3F)
		# Unsegmented messages have a small MIC
		upper_pdu = UpperEncryptedAccessPDU.from_bytes(b[1:], False, aid)
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


control_pdus: Dict[CTLOpcode, 'UnsegmentedControlLowerPDU'] = dict()


class UnsegmentedControlLowerPDU(LowerPDU):
	MAX_PARAMETERS_LEN = 88
	__slots__ = "opcode"

	def __init__(self, opcode: CTLOpcode): \
			self.opcode = opcode

	def to_bytes(self) -> bytes:
		return bytes([self.opcode & 0x3f]) + self.control_to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'UnsegmentedControlLowerPDU':
		opcode = CTLOpcode(b[0] & 0x3F)
		parameters = b[1:]
		return control_pdus[opcode].control_from_bytes(parameters)

	def control_to_bytes(self) -> bytes:
		raise NotImplementedError()

	@classmethod
	def control_from_bytes(cls, b: bytes):
		raise NotImplementedError()


class Heartbeat(UnsegmentedControlLowerPDU):
	__slots__ = "rfu", "init_ttl", "features"

	def __init__(self, init_ttl: TTL, features: Features, rfu: bool = False) -> None:
		super().__init__(CTLOpcode.HEARTBEAT)
		self.rfu = rfu
		self.init_ttl = init_ttl
		self.features = features

	def control_to_bytes(self) -> bytes:
		return ((self.init_ttl.value & 0x3F) | (self.rfu << 7)).to_bytes(1, byteorder="little") \
			   + self.features.to_bytes(2, byteorder="little")

	@classmethod
	def control_from_bytes(cls, b: bytes) -> 'Heartbeat':
		assert len(b) == 3
		rfu = (b[0] & 0x80) != 0
		ttl = TTL(b[0] & 0x3F)
		features = Features.from_bytes(b[1:], byteorder="little")
		return cls(ttl, features, rfu)


control_pdus[CTLOpcode.HEARTBEAT] = Heartbeat


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


LowerSegmentedPDU = Union[SegmentedAccessLowerPDU, SegmentedControlLowerPDU]


class BlockAck:
	LEN = 4  # 4 bytes/32 bits
	__slots__ = "block", "seg_n"

	def __init__(self, block: int, seg_n: int):
		self.block = block
		self.seg_n = seg_n

	def _check_index(self, index: int):
		if index < 0:
			raise IndexError(f"index can't be negative : {index}")
		if index >= self.seg_n:
			raise IndexError(f"index {index} is bigger than the block ack size {self.seg_n} bits")

	def set(self, index: int):
		self._check_index(index)
		self.block |= 1 << index

	def get(self, index: int) -> bool:
		self._check_index(index)
		return (self.block & (1 << index)) != 0

	def to_bytes(self) -> bytes:
		return self.block.to_bytes(self.LEN, byteorder="big")

	@classmethod
	def from_bytes(cls, b: bytes) -> 'BlockAck':
		if len(b) != cls.LEN:
			raise ValueError(f"expect {cls.LEN} bytes but got {len(b)}")
		return cls(int.from_bytes(b, byteorder="big"), cls.LEN * 8)

	def get_unacked_pdu_indexes(self) -> Generator[int, None, None]:
		for i in range(self.seg_n):
			if not self.get(i):
				yield i

	def get_acked_pdu_indexes(self) -> Generator[int, None, None]:
		for i in range(self.seg_n):
			if self.get(i):
				yield i


class SegmentAcknowledgementPDU(UnsegmentedControlLowerPDU):
	__slots__ = "obo", "seq_zero", "block_ack"

	def __init__(self, obo: bool, seq_zero: int, block_ack: BlockAck):
		super().__init__(CTLOpcode.ACK)
		self.obo = obo
		self.seq = seq_zero
		self.block_ack = block_ack

	def control_to_bytes(self) -> bytes:
		return make_seq_zero(self.obo, self.seq_zero, 0, 0)[0:2] + self.block_ack.to_bytes()

	@classmethod
	def control_from_bytes(cls, b: bytes) -> 'SegmentAcknowledgementPDU':
		seq_zero_obo = int.from_bytes(b [:2], byteorder="big")
		block_ack = BlockAck.from_bytes(b[2:2 + 4])
		return cls(obo=(seq_zero_obo & 0x7000) == 0x7000, seq_zero=(seq_zero_obo >> 2) & 0x1FFF, block_ack=block_ack)


class SegmentSrc:
	__slots__ = "src", "seq_auth"

	def __init__(self, src: UnicastAddress, seq_auth: SeqAuth):
		self.src = src
		self.seq_auth = seq_auth


class SegmentAssembler:
	def __init__(self, src: UnicastAddress, first_pdu: LowerPDU):
		if isinstance(first_pdu, SegmentedControlLowerPDU):
			self.ctl = True
		elif isinstance(first_pdu, SegmentedAccessLowerPDU):
			self.ctl = False
		else:
			raise ValueError("unexpected lower pdu type")
		pdu = self.verify(first_pdu)
		self.src = src
		self.szmic = pdu.szmic
		self.seq_zero = pdu.seq_zero
		self.seg_n = first_pdu.seg_n
		self.seg_mask = (2 ** self.seg_n) - 1
		self.block_ack = BlockAck(self.seg_mask, self.seg_n)
		self.seg_len = pdu.SEG_LEN
		self.known_len = 0
		self.max_len = self.seg_n * self.seg_len
		self.data = bytearray(self.max_len)
		self.obo = False

	@staticmethod
	def ack_timer(ttl: int) -> int:
		return 150 + ttl * 50

	@staticmethod
	def incomplete_timer() -> int:

		return 10000

	def verify(self, pdu: LowerPDU) -> Union[SegmentedAccessLowerPDU, SegmentedControlLowerPDU]:
		if self.ctl and isinstance(pdu, SegmentedControlLowerPDU):
			return cast(SegmentedControlLowerPDU, pdu)
		elif not self.ctl and isinstance(pdu, SegmentedAccessLowerPDU):
			return cast(SegmentedAccessLowerPDU, pdu)
		else:
			raise ValueError(f"unexpected lower pdu type ctl:{self.ctl} pdu:{pdu}")

	def insert_segment(self, seg_i: int, data: bytes):
		position = self.seg_n * self.seg_len
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
		self.block_ack = self.block_ack.set(seg_i)

	def insert_ctl(self, pdu: SegmentedControlLowerPDU):
		assert self.ctl, "trying to insert a control pdu into an access segment assembly"
		self.insert_segment(pdu.seg_o, pdu.segment)

	def insert_access(self, pdu: SegmentedAccessLowerPDU):
		assert not self.ctl, "trying to insert a access pdu into a ctl segment assembly"
		self.insert_segment(pdu.seg_o, pdu.segment)

	def upper_bytes(self) -> bytes:
		assert self.is_done() and self.known_len, "segment assemble must be done before getting upper transport pdu"
		return self.data[:self.known_len]

	def is_done(self) -> bool:
		return self.block_ack == 0

	def get_upper_control(self) -> 'UnsegmentedControlLowerPDU':
		assert self.ctl
		return UnsegmentedControlLowerPDU.from_bytes(self.upper_bytes())

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

	def ack(self) -> SegmentAcknowledgementPDU:
		return SegmentAcknowledgementPDU(self.obo, self.seq_zero, self.block_ack)


class Scheduler:
	pass


class Reassemblers:
	__slots__ = "contexts"

	def __init__(self):
		self.contexts: Dict[SegmentSrc, SegmentAssembler] = dict()

	def handle_control(self, control_pdu: UnsegmentedControlLowerPDU):
		pass

	def handle(self, src: UnicastAddress, pdu: LowerSegmentedPDU) -> Optional[UpperEncryptedAccessPDU]:
		seg_src = SegmentSrc(src, pdu.seq_zero)
		if seg_src not in self.contexts:
			if pdu.seg_o == 0:
				self.contexts[seg_src] = SegmentAssembler(src, pdu)
				return
			else:
				# TODO: Allow reassembly out of order
				raise ValueError("unknown segment pdu")
		else:
			assembler: SegmentAssembler = self.contexts[seg_src]
			assembler.insert(pdu)
			if assembler.is_done():
				del self.contexts[seg_src]
				if assembler.ctl:
					self.handle_control(assembler.get_upper_control())
				else:
					upper = assembler.get_upper()
					return upper
			return None


class SegmentedMessage:
	__slots__ = "pdus", "block_ack", "seg_n", "ttl", "retransmit"

	def __init__(self, pdus: List[LowerSegmentedPDU], ttl: Optional[TTL] = 10, retransmit: Optional[int] = 3):
		self.pdus = pdus
		self.seg_n = pdus[0].seg_n
		self.block_ack = BlockAck(0, self.seg_n)
		self.ttl = ttl
		self.retransmit = retransmit

	def ack_timeout(self) -> None:
		if self.retransmit <= 0:
			raise ValueError("retransmits is 0")
		self.retransmit -= 1

	def interval(self) -> int:
		return 200 * 50 * self.ttl.value

	def get_unacked(self) -> Generator[LowerSegmentedPDU, None, None]:
		for i in self.block_ack.get_unacked_pdu_indexes():
			yield self.pdus[i]

	def done(self) -> bool:
		return self.block_ack == 0

	def handle_ack(self, ack: SegmentAcknowledgementPDU):
		if ack.block_ack > self.block_ack:
			return
		self.block_ack = ack.block_ack


def make_lower_pdu(lower_pdu_bytes: bytes, ctl: bool):
	if (lower_pdu_bytes[0] & 0x80) == 1:
		if ctl:
			if lower_pdu_bytes[0] == 0x80:
				return SegmentedAccessLowerPDU.from_bytes(lower_pdu_bytes)
			else:
				return SegmentedControlLowerPDU.from_bytes(lower_pdu_bytes)
	else:
		if ctl:
			return UnsegmentedControlLowerPDU.from_bytes(lower_pdu_bytes)
		else:
			return UnsegmentedAccessLowerPDU.from_bytes(lower_pdu_bytes)

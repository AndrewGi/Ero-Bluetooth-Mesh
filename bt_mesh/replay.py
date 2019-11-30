from .mesh import *
from . import net
import datetime

class ReplayEntry(Serializable):
	__slots__ = "src", "new_iv", "seq", "last_seen"

	def __init__(self, src: UnicastAddress, seq: Seq, new_iv: bool, last_seen: datetime.datetime):
		self.src = src
		self.seq = seq
		self.new_iv = new_iv
		self.last_seen = last_seen

	def update_seq(self, new_seq: Seq, new_iv: Optional[bool] = False):
		if new_seq < self.seq and (self.new_iv == new_iv or new_iv):
			raise ValueError(f"entry:{str(self)} new_seq:{new_seq} niv:{new_iv}")
		self.seq = new_seq
		if new_iv:
			self.new_iv = True

	def as_retired(self) -> None:
		if not self.new_iv:
			raise ValueError("IV already old, should be deleted not retired")
		self.new_iv = False

	def __str__(self) -> str:
		return f"(src:{str(self.src)}, seq:{self.seq}, niv: {self.new_iv})"

	def __hash__(self) -> int:
		"""
		Hash of new_iv is either 0, 1. Hash of src is 0x0-0xFFFF.
		The combined hash looks like:
		I: IV Hash Bit
		S: Src address hash bits

		LSB					MSB
		ISSS SSSS  SSSS SSSS S
		:return:
		"""
		return (hash(self.new_iv)) | (hash(self.src) << 1)


class ReplayCache(Serializable):
	__slots__ = "iv_index", "seq_set"

	def __init__(self, iv_index: IVIndex, seq_set: Dict[UnicastAddress, ReplayEntry]):
		self.iv_index = iv_index
		self.seq_set: Dict[UnicastAddress, ReplayEntry] = seq_set

	def to_dict(self) -> DictValue:
		return {
			"iv_index": self.iv_index.value,
			"seq_set": {
				address.value: entry.to_dict() for address, entry in self.seq_set.items()
			}
		}

	@classmethod
	def from_dict(cls, d: DictValue) -> Any:
		iv_index = IVIndex(d["iv_index"])
		seq_set: Dict[UnicastAddress, ReplayEntry] = {
			UnicastAddress(address): ReplayEntry.from_dict(entry) for address, entry in d.items()
		}
		return cls(iv_index, seq_set)

	def update_iv(self, new_iv: IVIndex):
		if self.iv_index.next_iv() != new_iv:
			raise ValueError(f"iv index should be 0x{self.iv_index:X}+1 not 0x{new_iv:X}")
		self.iv_index = new_iv
		entry: ReplayEntry
		# Dump and old IVs and retire all the others
		self.seq_set = {
			entry.src: entry.as_retired() for entry in self.seq_set if entry.new_iv
		}

	def get(self, address: UnicastAddress) -> ReplayEntry:
		return self.seq_set[address]

	def get_seq(self, address: UnicastAddress) -> Seq:
		return self.get(address).seq

	def set(self, address: UnicastAddress, seq: Seq) -> None:
		self.seq_set[address].update_seq(seq)

	def verify_net(self, pdu: net.PDU) -> bool:
		if pdu.src not in self.seq_set:
			self.set(pdu.src, pdu.seq)
			return True
		else:
			if self.get(pdu.src) < pdu.seq:
				self.set(pdu.src, pdu.seq)
				return True
			else:
				return False

from typing import *
from enum import IntEnum, IntFlag, Enum
from uuid import UUID
from .serialize import *


class KeyIndex(U16):
	INDEX_LEN = 12
	byteorder = "little"

	def join(self, other: 'KeyIndex') -> bytes:
		index_0 = self.value
		index_1 = other.value
		return U24(index_0 | (index_1 << self.INDEX_LEN)).to_bytes()

	@classmethod
	def unjoin(cls, b: bytes) -> Tuple['KeyIndex', 'KeyIndex']:
		if len(b) != 2:
			raise ValueError(f"expected 2 bytes got {len(b)}")
		both_indexes = U24.from_bytes(b)
		key_mask = (1 << cls.INDEX_LEN) - 1
		index_0 = both_indexes.value & key_mask
		index_1 = (both_indexes.value >> cls.INDEX_LEN) & key_mask
		return KeyIndex(index_0), KeyIndex(index_1)


class NetKeyIndex(KeyIndex):
	pass


class AppKeyIndex(KeyIndex):
	pass


class CompanyID(U16):
	byteorder = "little"



class ProductID(U16):
	pass


class VersionID(U16):
	pass


class NID(U8):
	byteorder = "big"  # network pdu
	pass


class AID(U8):
	pass


class Seq(U24):
	byteorder = "big"  # network pdu
	pass


SeqAuth = NewType("SeqAuth", int)
SeqZero = NewType("SeqZero", int)


class RSSI(I8):
	pass


class NetworkID(U64):
	byteorder = "big"


class NetworkStateFlags(IntFlag):
	KeyRefresh = 0
	IVUpdate = 1


class IVIndex(U32):
	IV_MAX = 2 ** 32 - 1

	def ivi(self) -> bool:
		return self.value % 2 == 1

	def next_iv(self) -> 'IVIndex':
		if self == self.IV_MAX:
			raise OverflowError("iv index at max")
		return self + 1

	def prev_iv(self) -> 'IVIndex':
		if self == type(self)(0):
			raise OverflowError("iv index at min")
		return self - 1


class MIC:
	__slots__ = ('bytes_be',)

	def __init__(self, bytes_be: bytes):
		self.bytes_be = bytes_be

	def mic_len(self) -> int:
		return len(self.bytes_be) * 8

	def __len__(self) -> int:
		return len(self.bytes_be)


class NonceType(IntEnum):
	NETWORK = 0x00
	APPLICATION = 0x01
	DEVICE = 0x02
	PROXY = 0x03
	RFU = 0x04
	END = 0xFF


class TTL(U8):
	MAX_TTL = 127
	DEFAULT_TTL = 255
	def __init__(self, ttl: int):
		if ttl == self.DEFAULT_TTL:
			super().__init__(ttl)
		if 0 <= ttl <= self.MAX_TTL:
			super().__init__(ttl)
		else:
			raise ValueError(f"ttl too high: {ttl}")


class Address(U16):
	MAX_ADDRESS = 0xFFFF

	def __init__(self, addr: int) -> None:
		if 0 <= addr < self.MAX_ADDRESS:
			super().__init__(addr)
		else:
			raise ValueError(f"address higher than allowed 16 bit range {addr:x}")

	@classmethod
	def from_str(cls, s: str) -> Union['GroupAddress', 'VirtualAddress', 'UnicastAddress']:
		if "-" in s:
			# probably virtual address
			return VirtualAddress(UUID(s))
		return cls.from_int(int(s, base=16))

	@classmethod
	def from_dict_key(cls, d: DictValue, key: str) -> Union['GroupAddress', 'VirtualAddress', 'UnicastAddress']:
		if isinstance(d[key], str):
			return VirtualAddress(uuid=UUID(hex=d[key]))
		elif isinstance(d[key], int):
			return cls.from_int(d[key])
		else:
			raise TypeError(f"unrecognized dict type. key: {key} d: {d}")

	@classmethod
	def from_int(cls, i: int) -> Union['GroupAddress', 'UnicastAddress']:
		try:
			return UnicastAddress(i)
		except ValueError:
			pass

		try:
			return GroupAddress(i)
		except ValueError:
			pass
		raise ValueError(f"unknown address {i}")


class GroupAddress(Address):
	GROUP_MASK = 0xC000

	def __init__(self, addr: int) -> None:
		if self.GROUP_MASK & addr != self.GROUP_MASK:
			raise ValueError(f"{hex(addr)} is not a group address")
		super().__init__(addr)


class UnicastAddress(Address):
	def __init__(self, addr: int):
		if 0xC000 & addr != 0:
			raise ValueError(f"{hex(addr)} is not a unicast address")
		super().__init__(addr)

	@classmethod
	def last(cls) -> 'UnicastAddress':
		return cls(0x3FFF)


class VirtualAddress(Address):
	__slots__ = "uuid",

	VIRTUAL_AES_CMAC: Callable[[UUID, ], bytes]

	def addr(self) -> Address:
		if not self.VIRTUAL_AES_CMAC:
			raise ValueError("missing virtual aes cmac (did you import crypto?)")
		return Address(int.from_bytes(self.VIRTUAL_AES_CMAC(self.uuid)[14:15], byteorder="big") & 0x3FFF | 0x8000)

	def __init__(self, uuid: UUID):
		self.uuid = uuid
		super().__init__(self.addr().value)


class TransactionNumber(U8):
	pass


class TransmitParameters(ByteSerializable, Serializable):
	__slots__ = "count", "steps"
	STEP_LEN: int

	def __init__(self, count: int, steps: int) -> None:
		if count > 0x07:
			raise ValueError(f"count {count}>0x07")
		if steps > 0x1F:
			raise ValueError(f"steps {steps}>0x1F")
		self.count = count
		self.steps = steps

	def interval_ms(self) -> int:
		return self.STEP_LEN * (self.steps + 1)

	def to_bytes(self) -> bytes:
		return U8(self.count | (self.steps << 3)).to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'TransmitParameters':
		v = U8.from_bytes(b).value
		count = v & 0x3
		steps = (v >> 3) & 0x1F
		return cls(count=count, steps=steps)

	def to_dict(self) -> Dict[str, Any]:
		return {
			"count": self.count,
			"steps": self.steps
		}

	@classmethod
	def from_dict(cls, d: Dict[str, Any]) -> 'TransmitParameters':
		return cls(d["count"], d["steps"])


class NetworkTransmitParameters(TransmitParameters):
	STEP_LEN = 10


class PublishRetransmitParameters(TransmitParameters):
	STEP_LEN = 50


class RelayRetransmitParameters(TransmitParameters):
	STEP_LEN = 10


class StepResolution(IntFlag):
	HundredMilliseconds = 0
	OneSecond = 1
	TenSeconds = 2
	TenMinutes = 3

	def to_milliseconds(self) -> int:
		if self == self.HundredMilliseconds:
			return 100
		elif self == self.OneSecond:
			return 1 * 1000
		elif self == self.TenSeconds:
			return 10 * 1000
		elif self == self.TenMinutes:
			return 10 * 60 * 1000


class PublishPeriod(ByteSerializable, Serializable):
	__slots__ = "steps_num", "steps_res"

	def __init__(self, steps_num: int, steps_res: StepResolution) -> None:
		if 0 <= steps_num < 0x40:
			self.steps_num = steps_num
			self.steps_res = steps_res
		raise ValueError(f"step num must be 0<={steps_res}<0x40")

	def period(self) -> int:
		return self.steps_res.to_milliseconds() * self.steps_num

	def to_bytes(self) -> bytes:
		return (((self.steps_res & 0x3) << 6) | (self.steps_num & 0x3F)).to_bytes(1, byteorder="little")

	def to_dict(self) -> Dict[str, Any]:
		return {
			"steps_num": self.steps_num,
			"steps_res": self.steps_res.value
		}

	@classmethod
	def from_dict(cls, d: DictValue) -> Any:
		steps_num = d["steps_num"]
		steps_res = StepResolution(d["steps_res"])
		return cls(steps_num, steps_res)

	@classmethod
	def from_bytes(cls, b: bytes) -> 'PublishPeriod':
		if len(b) != 1:
			raise ValueError(f"len of bytes should be 1 not {len(b)}")
		steps_num = b[0] & 0x3F
		steps_res = StepResolution(b[0] >> 6)
		return cls(steps_num, steps_res)


class Features(IntFlag):
	Relay = 1
	Proxy = 2
	Friend = 4
	LowPower = 8


class LocationDescriptor(U16):
	pass

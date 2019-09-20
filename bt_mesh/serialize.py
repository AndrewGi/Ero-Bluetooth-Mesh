from typing import *
from functools import total_ordering


class ByteSerializable:
	def to_bytes(self) -> bytes:
		raise NotImplementedError()

	@classmethod
	def from_bytes(cls, b: bytes) -> Any:
		raise NotImplementedError()


class Serializable:
	def to_dict(self) -> Dict[str, Any]:
		raise NotImplementedError()

	@classmethod
	def from_dict(cls, d: Dict[str, Any]):
		raise NotImplementedError()


IntOperand = Union['Integer', int]


@total_ordering
class Integer(ByteSerializable):
	__slots__ = "value",
	length: int
	signed: bool
	byteorder: str

	def __init__(self, value: Optional[int] = 0) -> None:
		self._check(value)
		self.value = value

	def _check(self, v: int) -> None:
		if self.is_unsigned() and v < 0:
			raise ValueError(f"integer is unsigned and value is {v}")
		if v.bit_length() > (self.length * 8):
			raise ValueError(f"integer {v} is bigger than the maximum {2 ** (self.length - self.signed) - 1}")

	def is_unsigned(self) -> bool:
		return not self.signed

	def is_signed(self) -> bool:
		return self.signed

	def to_bytes(self) -> bytes:
		return self.to_bytes_endian(self.byteorder)

	def to_bytes_endian(self, byteorder: str) -> bytes:
		return self.value.to_bytes(self.length, byteorder)

	def set_bit(self, bit_index: int) -> None:
		if not 0 <= bit_index < self.length * 8:
			raise IndexError(f"index {bit_index}>{self.length * 8}")
		self.value |= 1 << bit_index

	def get_bit(self, bit_index: int) -> bool:
		if not 0 <= bit_index < self.length * 8:
			raise IndexError(f"index {bit_index}>{self.length * 8}")
		return (self.value & (1 << bit_index)) != 0

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Integer':
		if len(b) != cls.length:
			raise ValueError(f"expect {cls.length} bytes but got {len(b)}")
		return cls(int.from_bytes(b, byteorder=cls.byteorder, signed=cls.signed))

	@staticmethod
	def _value(v: IntOperand) -> int:
		return v if isinstance(v, int) else v.value

	@classmethod
	def new(cls, v: int) -> 'Integer':
		return cls(v)

	def __add__(self, other: IntOperand) -> 'Integer':
		return self.new(self.value + self._value(other))

	def __sub__(self, other: IntOperand) -> 'Integer':
		return self.new(self.value - self._value(other))

	def __mul__(self, other: IntOperand) -> 'Integer':
		return self.new(self.value * self._value(other))

	def __neg__(self) -> 'Integer':
		if self.signed:
			return self.new(-self.value)
		else:
			return self.new(2 ** (self.length * 8) - self.value)

	def __eq__(self, other: IntOperand) -> bool:
		return self.value == self._value(other)

	def __lt__(self, other: IntOperand) -> bool:
		return self.value < self._value(other)


DEFAULT_ENDIAN = "little"


class Unsigned(Integer):
	signed = False
	byteorder = DEFAULT_ENDIAN


class Signed(Integer):
	signed = True
	byteorder = DEFAULT_ENDIAN


class U8(Unsigned):
	length = 1


class I8(Signed):
	length = 1


class U16(Unsigned):
	length = 2


class I16(Signed):
	length = 2


class U24(Unsigned):
	length = 3


class I24(Signed):
	length = 3


class U32(Unsigned):
	length = 4


class I32(Signed):
	length = 4


class U64(Unsigned):
	length = 8


class I64(Signed):
	length = 8

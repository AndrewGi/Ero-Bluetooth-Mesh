from typing import *
from .mesh import *
import struct
ModelID = NewType("ModelID", int)


class Opcode:
	__slots__ = ("opcode", "company_id")

	def __init__(self, opcode: int, company_id: Optional[int] = None):
		if company_id is None:
			if opcode < 0b01111111:
				self.opcode = opcode  # One octet
			elif 0b01111111 < opcode < 0b0100000000000000:
				self.opcode = opcode
			else:
				raise ValueError(f"invalid opcode {opcode}")
		else:
			if company_id < 0xFFFF and opcode < 64:
				self.company_id = company_id
				self.opcode = opcode

	def __len__(self) -> int:
		if self.company_id is not None:
			return 3
		elif self.opcode < 0b01111111:
			return 1
		else:
			return 2

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Opcode':
		return cls(int.from_bytes(b, 'little'))

	def as_bytes(self) -> bytes:
		l = len(self)
		if l == 3:
			return struct.pack("<BH", self.opcode | 0xC0, self.company_id)
		elif l == 2:
			return struct.pack("<H", self.opcode | 0x8000)
		elif l == 1:
			return struct.pack("<B", self.opcode)
		raise NotImplementedError()

class ModelIdentifier:
	__slots__ = ("company_id","model_id")
	def __init__(self, model_id: ModelID, company_id: Optional[CompanyID] = SIGCompanyID):
		self.model_id = model_id
		self.company_id = company_id

class AccessPayload:
	__slots__ = ("opcode", "parameters")

	def __init__(self, opcode: Opcode, parameters: bytes):
		if len(parameters) > 380:
			raise OverflowError("access payload too big")
		self.opcode = opcode
		self.parameters = parameters

	def as_bytes(self) -> bytes:
		return self.opcode.as_bytes() + self.parameters

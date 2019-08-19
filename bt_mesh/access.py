from typing import *
from .mesh import *
import struct

ModelID = NewType("ModelID", int)


class ModelIdentifier:
	__slots__ = "company_id", "model_id"

	def __init__(self, company_id: CompanyID, model_id: ModelID):
		self.company_id = company_id
		self.model_id = model_id


ACK_TIMEOUT = 30  # 30 seconds is minimum act timeout


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
		opcode_size = (b[0] >> 6)
		if opcode_size < 2:
			if b[0] == 0b01111111:
				raise ValueError(f"{b[0]:x} RFU")
			opcode_size = 1
		opcode = b[0] & 0xC0
		company_id = None
		if opcode_size == 3:
			company_id = struct.unpack("<H", b[1:3])
		elif opcode_size == 2:
			opcode = (opcode << 8) | b[1]
		return cls(opcode, company_id)

	def as_bytes(self) -> bytes:
		opcode_len = len(self)
		if opcode_len == 3:
			return struct.pack("<BH", self.opcode | 0xC0, self.company_id)
		elif opcode_len == 2:
			return struct.pack("<H", self.opcode | 0x8000)
		elif opcode_len == 1:
			return struct.pack("<B", self.opcode)
		raise NotImplementedError()


class ModelIdentifier:
	STRUCT = struct.Struct("<HH")
	__slots__ = ("company_id", "model_id")

	def __init__(self, model_id: ModelID, company_id: Optional[CompanyID] = SIGCompanyID):
		self.model_id = model_id
		self.company_id = company_id

	def to_bytes(self) -> bytes:
		return self.STRUCT.pack(self.company_id, self.model_id)

	@classmethod
	def from_bytes(cls, b: bytes):
		company_id, model_id = cls.STRUCT.unpack(b)
		return cls(model_id, company_id)


class AccessPayload:
	MAX_SIZE = 380
	__slots__ = ("opcode", "parameters", "big_mic")

	def __init__(self, opcode: Opcode, parameters: bytes):
		if len(parameters) > 380:
			raise OverflowError("access payload too big")
		self.opcode = opcode
		self.parameters = parameters

	def __len__(self) -> int:
		return len(self.opcode) + len(self.parameters)

	def to_bytes(self) -> bytes:
		return self.opcode.as_bytes() + self.parameters

	@classmethod
	def from_bytes(cls, b: bytes) -> 'AccessPayload':
		opcode = Opcode.from_bytes(b)
		return cls(opcode, b[len(opcode):])


class AccessMessage:
	__slots__ = "src", "dst", "opcode", "payload", "big_mic", "ttl", "appkey_index", "netkey_index", "device_key", "force_segment"

	def __init__(self, src: Address, dst: Address, ttl: TTL, opcode: Opcode, payload: bytes,
				 appkey_index: Optional[AppKeyIndex],
				 netkey_index: NetKeyIndex, big_mic: Optional[bool] = False, device_key: Optional[bool] = False,
				 force_segment: Optional[bool] = False):
		if device_key and appkey_index is not None:
			raise ValueError("device key True but also given an appkey_index")
		self.src = src
		self.dst = dst
		self.ttl = ttl
		self.opcode = opcode
		self.payload = payload
		self.appkey_index = appkey_index
		self.netkey_index = netkey_index
		self.big_mic = big_mic
		self.device_key = device_key
		self.force_segment = force_segment

	def access_payload(self) -> AccessPayload:
		return AccessPayload(self.opcode, self.payload)


class AccessHandler:
	__slots__ = "address",

	def __init__(self, address: 'AccessHandler') -> None:
		self.address = address

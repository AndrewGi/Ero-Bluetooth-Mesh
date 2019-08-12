from typing import *
from enum import IntEnum
from uuid import UUID

from . import crypto

KeyIndex = NewType("NetIndex", int)
NetKeyIndex = NewType("NetKeyIndex", KeyIndex)
AppKeyIndex = NewType("AppKeyIndex", KeyIndex)

CompanyID = NewType("CompanyID", int)
SIGCompanyID = CompanyID(0)

NID = NewType("NID", int)
AID = NewType("AID", int)
Seq = NewType("Seq", int)


def seq_bytes(seq: Seq):
	return seq.to_bytes(3, byteorder="big")


class IVIndex:
	__slots__ = "index",

	def __init__(self, index: int):
		self.index = index

	def ivi(self) -> bool:
		return self.index % 2 == 1


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


class TTL(int):
	MAX_TTL = 127

	def __init__(self, ttl: int):
		if 0 <= ttl <= self.MAX_TTL:
			super().__init__(ttl)
		else:
			raise ValueError(f"ttl too high: {ttl}")

class Address(int):
	MAX_ADDRESS = 0xFFFF

	def __init__(self, addr: int):
		if addr > self.MAX_ADDRESS:
			raise ValueError(f"address higher than allowed 16 bit range {addr:x}")
		super().__init__(addr)


class GroupAddress(Address):
	def __init__(self, addr: int):
		if 0xC000 & addr != 0xC000:
			raise ValueError(f"{hex(addr)} is not a group address")
		super().__init__(addr)


class UnicastAddress(Address):
	def __init__(self, addr: int):
		if 0xC000 & addr != 0:
			raise ValueError(f"{hex(addr)} is not a unicast address")
		super().__init__(addr)


class VirtualAddress(Address):
	SALT = crypto.s1("vtad")

	def addr(self) -> Address:
		return Address(int.from_bytes(crypto.aes_cmac(self.SALT, self.uuid.bytes)[14:15], byteorder="big") | 0x8000)

	def __init__(self, uuid: UUID):
		self.uuid = uuid
		super().__init__(self.addr())


class SensorDescriptor:
	PropertyID = NewType("PropertyID", int)
	__slots__ = ('property_id', 'positive_tolerance', 'negative_tolerance', 'sample_function', 'measurement_period'
																							   'update_interval')

	def __init__(self, property_id: PropertyID, positive_tolerance: int, negative_tolerance: int,
				 sample_function: int,
				 measurement_period: int, update_interval: int):
		self.property_id = property_id
		self.positive_tolerance = positive_tolerance
		self.negative_tolerance = negative_tolerance
		self.sample_function = sample_function
		self.measurement_period = measurement_period
		self.update_interval = update_interval

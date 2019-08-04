

def crc24(data: bytes):
	"""
	x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1
	:param data:
	:return:
	"""

class BTAddress:
	LEN = 6
	__slots__ = "address_bytes",
	def __init__(self, address_bytes: bytes):
		if len(address_bytes) != self.LEN:
			raise ValueError("bt address wrong len")
		self.address_bytes = address_bytes

	def __str__(self) -> str:
		return ":".join("{:02X}".format(i) for i in self.address_bytes)

class AccessAddress:
	LEN = 4
	__slots__ = "address_bytes",
	def __init__(self, address_bytes: bytes):
		if len(address_bytes) != self.LEN:
			raise ValueError("access address wrong len")
		self.address_bytes = address_bytes
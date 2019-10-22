from .. import serialize


class DeviceID(serialize.U16):
	pass


class Address(serialize.ByteSerializable):
	__slots__ = "octets",
	LEN = 6
	def __init__(self, octets: bytes) -> None:
		assert len(octets) == self.LEN
		self.octets = octets

	def to_bytes(self) -> bytes:
		return self.octets

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Address':
		return cls(b)

class DeviceInfoFlags(serialize.U32):
	pass

class DeviceInfo(serialize.Serializable):
	NAME_LEN = 8
	def __init__(self, device_id: DeviceID, name: str, address: Address, flags: DeviceInfoFlags, flags_type: serialize.U8,
				 features: bytes, pkt_type: serialize.U32, link_policy: serialize.U32, ):
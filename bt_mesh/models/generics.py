from ..mesh import *


class GenericStates:
	class OnOff(U8, Enum):
		Off = U8(0x00)
		On = U8(0x01)

	class Level(I16):
		pass

	class DefaultTransitionTime(ByteSerializable):
		__slots__ = "steps", "resolution"

		def to_bytes(self) -> bytes:
			pass

		@classmethod
		def from_bytes(cls, b: bytes) -> Any:
			pass

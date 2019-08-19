from typing import *

class ByteSerializable:
	def to_bytes(self) -> bytes:
		raise NotImplementedError()

	@classmethod
	def from_bytes(cls) -> Any:
		raise NotImplementedError()

class Serializable:
	def to_dict(self) -> Dict[str, Any]:
		raise NotImplementedError()

	@classmethod
	def from_dict(cls, d: Dict[str, Any]):
		raise NotImplementedError()

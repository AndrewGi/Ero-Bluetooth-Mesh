from typing import *

class Serializable:
	def to_dict(self) -> Dict[str, Any]:
		raise NotImplementedError()

	@classmethod
	def from_dict(cls, d: Dict[str, Any]):
		raise NotImplementedError()

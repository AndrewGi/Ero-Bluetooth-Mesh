from . import hci

class Interface:
	def open(self) -> None:
		raise NotImplementedError()

	def close(self) -> None:
		raise NotImplementedError()

	def is_open(self) -> bool:
		raise NotImplementedError()

	def

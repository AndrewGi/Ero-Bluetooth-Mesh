from typing import *
import enum
import abc

class OGF(enum.IntEnum):
	LEController = 0x80

class OCF(enum.IntEnum):
	pass

class HCICommand:
	__slots__ = "ogf", "ocf", "data"
	def __init__(self, ogf: OGF, ocf: OCF, data: bytes):
		#MIGHT NEED TO BE FIXXED TO 31 bytes
		self.ogf = ogf
		self.ocf = ocf
		self.data = data

	def __str__(self) -> str:
		return f"{int(self.ogf):2x} {int(self.ogf):4x} {' '.join(hex(i) for i in self.data)}"

class ToCommand(abc.ABC):
	@abstractmethod
	def to_command(self) -> HCICommand:
		pass
class Commands:
	class SetAdvertisingEnable:
		__slots__ = "enable",
		def __init__(self, enable: bool):
			self.enable = enable

		def to_command(self) -> HCICommand:
			return HCICommand(OGF.LEController, OCF(0x000A), bytes(int(self.enable)))

	class SetAdvertisingData:
		__slots__ = "data",
		def __init__(self, data: bytes):
			self.data = data

		def to_command(self) -> HCICommand:
			return HCICommand(OGF.LEController, OCF(0x0008), self.data)

	class SetAdvertisingParams:
		__slots__ = "min_interval", "max_interval", "advertisement_type", "own_addr_type", "direct_addr_type", "channel_map", "filter_policy"
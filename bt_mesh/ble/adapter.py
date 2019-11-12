from typing import *
import abc
from . import adv

class Adapter(abc.ABC):

	def __init__(self):
		self.on_advertisement: Optional[Callable[[adv.AdvReceived], None]] = None

	def handle_advertisement(self, advertisement: adv.AdvReceived) -> None:
		if self.on_advertisement:
			self.on_advertisement(advertisement)

	@abc.abstractmethod
	def reset(self):
		pass

	@abc.abstractmethod
	def set_advertisement(self, advertisement: adv.AdvData) -> None:
		pass

	def advertise(self, advertisement: adv.AdvData):
		pass
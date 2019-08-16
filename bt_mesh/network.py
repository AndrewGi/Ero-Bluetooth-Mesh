from typing import *
from .mesh import *
from . import crypto

class RemoteDevice:
	__slots__ = "primary_address", "element_count"

	def __init__(self, primary_address: UnicastAddress, element_count: int):
		self.primary_address = primary_address
		self.element_count = element_count

	def primary_element_address(self) -> UnicastAddress:
		return self.primary_address

	def last_element_address(self) -> UnicastAddress:
		return UnicastAddress(self.primary_address + self.element_count)

	def has_unicast_address(self, address: UnicastAddress) -> bool:
		return self.primary_element_address() <= address < self.last_element_address()

	def to_dict(self) -> Dict[str, Any]:
		return {
			"primary_address": self.primary_address,
			"element_count": self.element_count
		}

	@classmethod
	def from_dict(cls, d: Dict) -> 'RemoteDevice':
		return cls(primary_address=d["primary_address"], element_count=d["element_count"])


class Network:
	__slots__ = "global_context", "remote_devices", "end_address"

	def __init__(self, global_context: crypto.GlobalContext, remote_devices: Dict[UnicastAddress, RemoteDevice], end_address: UnicastAddress):
		self.remote_devices: Dict[UnicastAddress, RemoteDevice] = remote_devices
		self.global_context: crypto.GlobalContext = global_context
		self.end_address = end_address


	def get_by_address(self, address: UnicastAddress):
		for device in self.remote_devices.values():
			if device.has_unicast_address(address):
				return device

	def allocate_device(self, element_count: int) -> RemoteDevice:
		start_address = self.end_address
		self.end_address = UnicastAddress(self.end_address+element_count)
		device = RemoteDevice(start_address, element_count)
		self.remote_devices[start_address] = device
		return device

	def to_dict(self) -> Dict[str, Any]:
		return {
			"global_context": self.global_context.to_dict(),
			"remote_devices": {device.primary_address: device.to_dict() for device in self.remote_devices.values()}
		}

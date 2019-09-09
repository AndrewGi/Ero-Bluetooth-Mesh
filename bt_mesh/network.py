from typing import *
from .mesh import *
from . import crypto


class RemoteDevice(Serializable):
	__slots__ = "primary_address", "element_count", "device_key"

	def __init__(self, primary_address: UnicastAddress, element_count: int, device_key: Optional[crypto.DeviceKey] = None):
		self.primary_address = primary_address
		self.element_count = element_count
		self.device_key = device_key

	def primary_element_address(self) -> UnicastAddress:
		return self.primary_address

	def last_element_address(self) -> UnicastAddress:
		return self.primary_address + self.element_count

	def has_unicast_address(self, address: UnicastAddress) -> bool:
		return self.primary_element_address() <= address < self.last_element_address()

	def to_dict(self) -> Dict[str, Any]:
		return {
			"primary_address": self.primary_address,
			"element_count": self.element_count
		}

	@classmethod
	def from_dict(cls, d: Dict) -> 'RemoteDevice':
		return cls(primary_address=UnicastAddress(d["primary_address"]), element_count=d["element_count"])


class Network(Serializable):
	__slots__ = "global_context", "remote_devices", "end_address"

	# TODO: Something better than end_address
	def __init__(self, global_context: crypto.GlobalContext, remote_devices: Dict[UnicastAddress, RemoteDevice],
				 end_address: UnicastAddress):
		self.remote_devices: Dict[UnicastAddress, RemoteDevice] = remote_devices
		self.global_context: crypto.GlobalContext = global_context
		self.end_address = end_address

	def get_by_address(self, address: UnicastAddress):
		for device in self.remote_devices.values():
			if device.has_unicast_address(address):
				return device

	def allocate_device(self, element_count: int) -> RemoteDevice:
		start_address = self.end_address
		self.end_address += element_count
		device = RemoteDevice(start_address, element_count)
		self.remote_devices[start_address] = device
		return device

	def to_dict(self) -> Dict[str, Any]:
		return {
			"global_context": self.global_context.to_dict(),
			"remote_devices": {device.primary_address: device.to_dict() for device in self.remote_devices.values()},
		}

	@classmethod
	def from_dict(cls, d: Dict[str, Any]) -> 'Network':
		global_context = crypto.GlobalContext.from_dict(d["global_context"])
		remote_devices = dict()
		last_address = Address(0)
		for raw_device in d["remote_devices"]:
			device = RemoteDevice.from_dict(raw_device)
			remote_devices[device.primary_address] = device
			if device.last_element_address() > last_address:
				last_address = device.last_element_address()

		return cls(global_context, remote_devices, last_address)

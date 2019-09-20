from typing import *
from .mesh import *
from . import crypto


class RemoteDevice(Serializable):
	__slots__ = "primary_address", "element_count", "device_key"

	def __init__(self, primary_address: UnicastAddress, element_count: int,
				 device_key: Optional[crypto.DeviceKey] = None):
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
			"element_count": self.element_count,
			"device_key": self.device_key.hex() if self.device_key else None
		}

	@classmethod
	def from_dict(cls, d: Dict) -> 'RemoteDevice':
		device_key = crypto.DeviceKey.from_str(d["device_key"]) if "device_key" in d.keys() else None
		return cls(primary_address=UnicastAddress(d["primary_address"]), element_count=d["element_count"],
				   device_key=device_key)


class AddressSpace(Serializable):
	__slots__ = "unicasts", "groups", "virtual"

	def __init__(self) -> None:
		self.unicasts: Dict[UnicastAddress, RemoteDevice] = dict()
		self.groups = dict()
		self.virtual = dict()

	def _allocate_device(self, remote_device: RemoteDevice) -> None:
		self.unicasts[remote_device.primary_address] = remote_device

	def addresses(self) -> List[UnicastAddress]:
		return sorted(self.unicasts.keys())

	def find_empty_block(self, element_count: int) -> UnicastAddress:
		index = 0
		addresses = self.addresses()
		while index < len(addresses) - 1:
			start_address = self.unicasts[addresses[index]].last_element_address()
			end_address = addresses[index + 1]
			gap_size = end_address - start_address
			if gap_size.value > element_count:
				return start_address
			else:
				# no room in gap between addresses
				pass
			index += 1
		end_address = addresses[-1] + self.unicasts[addresses[-1]].element_count
		if end_address > UnicastAddress.last():
			raise OverflowError(f"no space for {element_count} elements")
		return end_address

	def allocate_device(self, element_count: int) -> RemoteDevice:
		address = self.find_empty_block(element_count)
		device = RemoteDevice(address, element_count)
		self.unicasts[address] = device
		return device

	def verify_space(self) -> None:
		addresses = self.addresses()
		current_end = self.unicasts[addresses[0]].last_element_address()
		for address in addresses[1:]:
			if address < current_end:
				raise OverflowError(f"{address} overflows with last {current_end}")
			current_end = self.unicasts[address].last_element_address()
		if current_end > UnicastAddress.last():
			raise OverflowError(f"current end {current_end} is > {UnicastAddress.last()}")

	def _insert_device(self, remote_device: RemoteDevice) -> None:
		if remote_device.primary_address in self.unicasts.keys():
			raise ValueError(f"{remote_device} already in remote devices")
		self.unicasts[remote_device.primary_address] = remote_device

	@classmethod
	def from_dict(cls, d: Dict[str, Any]) -> 'AddressSpace':
		remote_devices = [RemoteDevice.from_dict(raw_device) for raw_device in d["unicasts"]]
		space = cls()
		for device in remote_devices:
			space._insert_device(device)
		space.verify_space()
		return space

	def to_dict(self) -> Dict[str, Any]:
		return {
			"unicasts": [device.to_dict() for device in self.unicasts.values()]
		}


class Network(Serializable):
	__slots__ = "global_context", "addresses", "end_address"

	# TODO: Something better than end_address
	def __init__(self, global_context: crypto.GlobalContext, address_space: AddressSpace, end_address: UnicastAddress):
		self.addresses: AddressSpace = address_space
		self.global_context: crypto.GlobalContext = global_context
		self.end_address = end_address

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

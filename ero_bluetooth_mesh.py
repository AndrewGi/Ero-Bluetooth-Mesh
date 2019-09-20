from ero.ero import *
from ero import ero_apps
import sqlite3
import copy
import queue
from typing import *
import struct
import threading
import math
import functools
BLUETOOTH_MESH_APPLICATION_NAME = "bluetooth_mesh"

bluetooth_mesh_app = None  # type: BluetoothMeshApplication

DEFAULT_OUTGOING_TTL = 6

def mesh_app():
	return bluetooth_mesh_app

class BluetoothMeshDeviceInfo:
	__slots__ = ("address", "subnet_handle", "appkey_handle")
	def __init__(self, address: Address, subnet_handle: SubnetHandle, appkey_handle: AppkeyHandle):
		self.address = address # type: Address
		self.subnet_handle = subnet_handle # type: SubnetHandle
		self.appkey_handle = appkey_handle # type: AppkeyHandle


def get_btm_info(device: Device) -> Optional[Tuple[SubnetHandle, AppkeyHandle]]:

	raise NotImplementedError

class Message:
	__slots__ = ('network_id', 'src', 'dst', 'netkey_index', 'appkey_index', 'ttl', 'data')

	def __init__(self
				 , network_id: Optional[NetworkID]=None
				 , src: Optional[UnicastAddress]=None
				 , dst: Optional[Address]=None
				 , subnet_handle: Optional[SubnetHandle] = None
				 , appkey_handle: Optional[AppkeyHandle] = None
				 , data: Optional[bytes] = None
				 , rssi: Optional[int] = None
				 , ttl: Optional[int] = None
				 , ):
		self.network_id = network_id
		self.src = src
		self.dst = dst
		self.subnet_handle = subnet_handle
		self.appkey_handle = appkey_handle
		self.rssi = rssi
		self.ttl = ttl
		self.data = data

	"""
	@classmethod
	def from_event(cls, network_id: NetworkID, event_data: Dict[str, Union[int, str]]):
		self.network_id = NetworkID(network_id)
		self.src = make_address(event_data['src'])
		self.dst = make_address(event_data['dst'])
		self.subnet_handle = int(event_data['subnet_handle'])
		self.appkey_handle = int(event_data['appkey_handle'])
		self.adv_addr_type = event_data['adv_addr_type']  # TODO: find out about adv_addr_type
		self.adv_addr = event_data['adv_addr']  # TODO: bluetooth adv_addr type?
		self.rssi = int(event_data['rssi'])
		self.ttl = int(event_data['ttl'])
		self.data = bytes(event_data['data'])
	"""

	@classmethod
	def outgoing_message(cls, dest: Device, data: Optional[bytes] = None, ttl: Optional[int] = DEFAULT_OUTGOING_TTL):
		btm_info = get_btm_info(dest)
		if btm_info is None:
			raise ValueError("device not found in bluetooth database")
		return Message(network_id=dest.network_id, dst=btm_info.address)

	@classmethod
	def from_event(cls, event: Event):
		return cls.outgoing_message(event.device, event.event_data["data"])

	def as_dict(self):
		return {key: getattr(self, key) for key in self.__slots__}

	def is_valid(self) -> bool:
		return (self.network_id != 0
				and 0 < self.src.addr < 2 ** 16
				and 0 < self.dst.addr < 2 ** 16
				and 0 <= self.ttl <= 127
				and 0 <= len(self.data) <= 380)  # 380 bytes sanity check (max segmented payload is 380 irc)

	def get_src_device(self) -> Device:
		return self.src.get_device(self.network_id)


def make_address(raw_addr: int) -> Address:
	if raw_addr >= 2 ** 16 or raw_addr < 0:
		raise ValueError(f"{raw_addr} is not a 16 bit address")
	addr_type = 0xC000 & raw_addr
	if addr_type == 0:
		return UnicastAddress(raw_addr)
	elif addr_type == 0xC000:
		return GroupAddress(raw_addr)
	raise NotImplementedError(f"{raw_addr} unimplemented address type")



class Model(ero_apps.Application):
	@staticmethod
	def get_opcodes(model_id: ModelID) -> Dict[str, Opcode]:
		pass  # TODO: Get opcodes

	def add_opcode_handler(self, opcode_name: str, handler: Callable):
		self.opcode_handlers[self.opcodes[opcode_name]] = handler

	def __init__(self, name: str):
		super().__init__(name + "_model")
		self.model_name = name
		self.model_id = self.definition["model_id"]
		self.opcodes = self.get_opcodes(self.model_id)
		self.opcode_handlers = dict()  # type: Dict[Opcode, Callable]

	def send_opcode(self, device: Device, opcode: Opcode, data: Optional[bytes] = None):
		payload = AccessPayload(opcode=opcode, parameters=data)
		self.fire_event(Event(event_type=self.etid_of("bluetooth_mesh", "raw_incoming"),
							  application_id=self.app_id_of("bluetooth_mesh"),
							  device_id=device.device_id, network_id=device.network_id, happened_timestamp=datetime.datetime.now(),
							  event_data=payload.to_bytes(), event_id=None, event_uuid=None))

	def get_opcode(self, name: str) -> Opcode:
		raise NotImplementedError()

	def feed_event(self, event: Event):
		if event.event_type != self.etid_of("bluetooth_mesh", "raw_incoming"):
			return #not a bluetooth event
		event.event_data


class Sensor:
	pass


class SensorData:
	pass




class Element:
	def __init__(self):
		pass




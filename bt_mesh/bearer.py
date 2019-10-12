import enum
from typing import List, Callable, Optional

from . import beacon, mesh


class BearerType(enum.IntEnum):
	Advertisement = 1
	Gatt = 2
	Proxy = 3
	Other = 4


class Bearer:
	__slots__ = "recv_beacon", "recv_network_pdu"

	def __init__(self):
		self.recv_beacon: Optional[Callable[[beacon.Beacon, ], None]] = None
		self.recv_network_pdu: Optional[Callable[[beacon.Beacon, ], None]] = None

	@classmethod
	def bearer_type(cls):
		raise NotImplementedError()

	def send_network_pdu(self, network_pdu: bytes, parameters: mesh.TransmitParameters):
		raise NotImplementedError()

	def send_beacon(self, mesh_beacon_payload: beacon.Beacon):
		raise NotImplementedError()



class Bearers(Bearer):
	__slots__ = "bearers",

	def __init__(self):
		super().__init__()
		self.bearers: List[Bearer] = list()

	def add_bearer(self, new_bearer: Bearer):
		self.bearers.append(new_bearer)
		new_bearer.recv_beacon = self.recv_beacon
		new_bearer.recv_network_pdu = self.recv_network_pdu

	@classmethod
	def bearer_type(cls):
		return BearerType.Other

	def send_network_pdu(self, network_pdu: bytes, parameters: mesh.TransmitParameters):
		for b in self.bearers:
			b.send_network_pdu(network_pdu, parameters)

	def send_beacon(self, mesh_beacon_payload: beacon.Beacon):
		for b in self.bearers:
			b.send_beacon(mesh_beacon_payload)

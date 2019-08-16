import enum
from typing import List

from . import beacon


class BearerType(enum.IntEnum):
	Advertisement = 1
	Gatt = 2
	Proxy = 3
	Other = 4


class TransmitParameters:
	__slots__ = "times", "delay_ms"

	def __init__(self, times: int, delay_ms: int):
		self.times = times
		self.delay_ms = delay_ms


class Bearer:
	@classmethod
	def bearer_type(cls):
		raise NotImplementedError()

	def send_network_pdu(self, network_pdu: bytes, parameters: TransmitParameters):
		raise NotImplementedError()

	def send_beacon(self, mesh_beacon_payload: beacon.Beacon):
		raise NotImplementedError()

	def recv_network_pdu(self, network_pdu: bytes):
		raise AttributeError("recv_network_pdu should be overloaded")

	def recv_beacon(self, mesh_beacon_payload: beacon.Beacon):
		raise AttributeError("recv_beacon should be overloaded")


class Bearers(Bearer):
	__slots__ = "bearers",

	def __init__(self):
		self.bearers: List[Bearer] = list()

	def add_bearer(self, new_bearer: Bearer):
		self.bearers.append(new_bearer)
		new_bearer.recv_beacon = self.recv_beacon
		new_bearer.recv_network_pdu = self.recv_network_pdu

	@classmethod
	def bearer_type(cls):
		return BearerType.Other

	def send_network_pdu(self, network_pdu: bytes, parameters: TransmitParameters):
		for b in self.bearers:
			b.send_network_pdu(network_pdu, parameters)

	def send_beacon(self, mesh_beacon_payload: beacon.Beacon):
		for b in self.bearers:
			b.send_beacon(mesh_beacon_payload)

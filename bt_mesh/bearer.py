import enum
from abc import ABC
from typing import Optional

from . import beacon

class BearerType(enum.IntEnum):
	Advertisement = 1
	Gatt = 2
	Proxy = 3
	Other = 4


class Bearer:
	@classmethod
	def __init__(self, network=None):
		self.network = network

	@classmethod
	def bearer_type(cls):
		raise NotImplementedError()

	def send_network_pdu(self, network_pdu: bytes):
		raise NotImplementedError()

	def recv_network_pdu(self, network_pdu: bytes):
		raise NotImplementedError("this is my job")

	def recv_beacon(self, mesh_beacon_payload: beacon.UnprovisionedBeacon):
		self.network.handle_beacon(mesh_beacon_payload)


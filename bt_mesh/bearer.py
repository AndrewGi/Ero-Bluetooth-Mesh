import enum
from typing import Optional

class BearerType(enum.IntEnum):
	Advertisement = 1
	Gatt = 2
	Proxy = 3
	Other = 4



class Bearer:
	@classmethod
	def __init__(self, network = None):
		self.network = network

	def bearer_type(cls):
		raise NotImplementedError()

	def send(self, network_pdu: bytes):
		raise NotImplementedError()

	def recv_network_pdu(self, network_pdu: bytes):
		raise NotImplementedError("this is my job")

	def recv_beacon(self, mesh_beacon_payload: bytes):
		raise NotImplementedError("this is my job")

	def recv_pb_adv(self, pb_adv: bytes):
		raise NotImplementedError


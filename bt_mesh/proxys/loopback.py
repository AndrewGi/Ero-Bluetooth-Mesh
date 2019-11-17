from typing import *
from .. import bearer, beacon, mesh


class LoopbackAdapter(bearer.Bearer):

	def __init__(self, other: Optional['LoopbackAdapter'] = None) -> None:
		super().__init__()
		self.other = other

	def get_other(self) -> 'LoopbackAdapter':
		if not self.other:
			self.other = LoopbackAdapter(self)
		return self.other

	@classmethod
	def bearer_type(cls) -> bearer.BearerType:
		return bearer.BearerType.Other

	def send_network_pdu(self, network_pdu: bytes, parameters: mesh.TransmitParameters):
		if self.other:
			self.other.recv_network_pdu(network_pdu)
		else:
			raise ValueError("missing other loopback adapter")

	def send_beacon(self, mesh_beacon_payload: beacon.Beacon):
		if self.other:
			self.other.recv_beacon(mesh_beacon_payload)
		else:
			raise ValueError("missing other loopback adapter")

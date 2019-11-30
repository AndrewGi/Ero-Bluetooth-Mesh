
from ..bearers import pb_adv
from ..mesh import *


class DummyBearer(pb_adv.AdvBearer):

	def stop_adv(self):
		pass

	def open(self):
		pass

	def mtu(self) -> int:
		pass

	def close(self, reason):
		pass

	def send_generic_prov_pdus(self, pdus):
		pass

	def send_beacon(self, mesh_beacon_payload):
		pass

	def __init__(self):
		super().__init__()

	@classmethod
	def bearer_type(cls):
		return pb_adv.bearer.BearerType.Advertisement

	def send_pb_adv(self, pb_adv_pdu: bytes, repeat: Optional[bool] = False):
		print(f"send pb adv: {pb_adv_pdu.hex()}")

	def send_network_pdu(self, network_pdu: bytes, parameters: NetworkTransmitParameters):
		print(f"send net_pdu c:{parameters.count}s:{parameters.steps}b:{network_pdu.hex()}")

import datetime
import time
import threading
from typing import *
from . import bleson
from .. import beacon
from ..bearers import pb_adv
from ..mesh import *
class BlesonBearer(pb_adv.AdvBearer):

	def __init__(self):
		super().__init__()
		self.adapter = bleson.get_provider().get_adapter()
		self.adapter.adv_type = 0x03
		self.adapter.set_advertising_parameter()
		self.observer = bleson.Observer(self.adapter)
		self.observer.on_advertising_data = self.on_advertisement
		self.wait_time = 0.1
		self.observer.start()
		self.adapter_lock = threading.Lock()

	def stop_adv(self):
		self.adapter.stop_advertising()

	def on_advertisement(self, advertisement: bleson.Advertisement):
		if advertisement.network_pdu:
			self.recv_network_pdu(advertisement.network_pdu)

		if advertisement.beacon_payload:
			self.recv_beacon(beacon.Beacon.from_bytes(advertisement.beacon_payload))

		if advertisement.pb_adv_pdu:
			print(f"RECV: {advertisement.pb_adv_pdu.hex()}")
			self.recv_pb_adv(advertisement.pb_adv_pdu)

	@classmethod
	def bearer_type(cls):
		return pb_adv.bearer.BearerType.Advertisement

	def send_pb_adv(self, pb_adv_pdu: bytes, repeat: Optional[bool] = False):
		print(f"PB_ADV: {pb_adv_pdu.hex()}")
		self._send_adv(bleson.Advertisement(pb_adv_pdu=pb_adv_pdu), repeat)

	def send_network_pdu(self, network_pdu: bytes, parameters: RetransmitParameters):
		# TODO: packet scheduling
		for i in range(parameters.count):
			self._send_adv(bleson.Advertisement(network_pdu=network_pdu))
			if parameters.steps > 0:
				time.sleep((parameters.steps - 1)*.1)

	def _send_adv(self, advertisement: bleson.Advertisement, repeat: Optional[bool] = False):
		advertisement.flags = None
		with self.adapter_lock:
			if repeat:
				self.adapter.start_advertising(advertisement)
				return
			with bleson.Advertiser(self.adapter, advertisement):
				time.sleep(self.wait_time)


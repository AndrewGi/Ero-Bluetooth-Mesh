import time

import bleson
from .. import bearer

class BlesonBearer(bearer.Bearer):

	def __init__(self):
		super().__init__(None)
		self.adapter = bleson.get_provider().get_adapter()
		self.observer = bleson.Observer(self.adapter)
		self.observer.on_advertising_data = self.on_advertisement
		self.wait_time = 0.1

	def on_advertisement(self, advertisement):
		if advertisement.network_pdu:
			print(advertisement.network_pdu.hex())
			self.recv_network_pdu(advertisement.network_pdu)

	def bearer_type(cls):
		return bearer.BearerType.Advertisement

	def send(self, network_pdu: bytes):
		with bleson.Advertiser(self.adapter, bleson.Advertisement(network_pdu=network_pdu)):
			time.sleep(self.wait_time)



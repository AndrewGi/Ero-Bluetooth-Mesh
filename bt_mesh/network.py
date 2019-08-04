import datetime

from . import beacon, prov
import queue
import threading
from typing import *
class Network:
	def __init__(self):
		self.incoming_net_pdus = queue.Queue()
		self.handle_net_pdu_thread = threading.Thread(target=self._handle_net_pdus)
		self.handle_net_pdu_thread.start()
		self.incoming_beacons = queue.Queue()
		self.handle_beacon_thread = threading.Thread(target=self._handle_beacons)
		self.bearers = list() # type: List[bearer.Bearer]
		self.unprovisioned_devices = list() # type: List[beacon.UnprovisionedBeacon]
		self.provisioner = prov.Provisioner(None)

	def _handle_beacons(self):
		while True:
			item = self.incoming_beacons.get()
			if item is None:
				break
			self.provisioner.handle_beacon(item)
			self.incoming_beacons.task_done()



	def _handle_net_pdus(self):
		while True:
			item = self.incoming_net_pdus.get()
			if item is None:
				break
			self._handle_raw_net_pdu(item)
			self.incoming_net_pdus.task_done()

	def _handle_raw_net_pdu(self, raw_net_pdu: bytes):
		pass

	def _send_raw_network_pdu(self, raw_network_pdu: bytes):
		for b in self.bearers:
			b.send_network_pdu(raw_network_pdu)

	def add_bearer(self, bearer):
		bearer.network = self
		if not self.provisioner.pb_bearer:
			self.provisioner.set_bearer(bearer)
		self.bearers.append(bearer)

	def handle_beacon(self, in_beacon: beacon.UnprovisionedBeacon):
		if self.provisioner:
			self.provisioner.handle_beacon(in_beacon)



	def handle_raw_network_pdu(self, network_pdu: bytes):
		pass
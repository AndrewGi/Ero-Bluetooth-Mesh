from ..beacon import *
import unittest
class BeaconTest(unittest.TestCase):

	def test_unprovisioned(self):
		uuid = UUID(hex="70cf7c9732a345b691494810d2e9cbf4")
		oob = b"\xa0\x40"
		beacon = UnprovisionedBeacon(oob, uuid)
		b = bytes.fromhex("0070cf7c9732a345b691494810d2e9cbf4a040")
		self.assertEqual(beacon.to_bytes(), b)
		self.assertEqual(UnprovisionedBeacon.from_bytes(b), beacon)

	def test_unprovisioned_uri(self):
		uuid = UUID(hex="70cf7c9732a345b691494810d2e9cbf4")
		oob = b"\x40\x20"
		uri = "https://www.example.com/mesh/products/light-switch-v3"
		b = bytes.fromhex("0070cf7c9732a345b691494810d2e9cbf44020d97478b3")
		beacon = UnprovisionedBeacon(oob, uuid, hash_uri(uri.encode()))
		self.assertEqual(beacon.to_bytes(), b)
		self.assertEqual(UnprovisionedBeacon.from_bytes(b), beacon)

	def test0_secure_beacon(self):
		flags = NetworkStateFlags.IVUpdate
		network_id = NetworkID(0xAEBBFFEE11225544)
		iv_index = IVIndex(0xEF12F4)
		auth_value = SecureBeaconAuthValue
		SecureBeacon(flags, network_id, iv_index, )
import unittest
from ..mesh import *
from .. import pb_generic, crypto
from ..bearers import pb_adv, prov
class PBAdvTests(unittest.TestCase):

	def setUp(self) -> None:
		self.link_id = pb_adv.LinkID(0x23AF5850)
		self.prov_public_key: crypto.ECCPublicKey = crypto.ECCPublicKey.from_bytes_hex("""
			2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd
			919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f
				""")
		self.prov_private_key = self.prov_public_key.make_private_key(
			0x06a516693c9aa31a6084545d0c5db641b48572b97203ddffb7ac73f7d0457663
		)

		self.device_public_key: crypto.ECCPublicKey = crypto.ECCPublicKey.from_bytes_hex("""
			529aa0670d72cd6497502ed473502b037e8803b5c60829a5a3caa219505530ba
			f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc
				""")
		self.device_private_key = self.prov_public_key.make_private_key(
			0x0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279
		)

		self.ecdh = crypto.ECDHSharedSecret(bytes.fromhex(
			"ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69"
		))

		self.prov_random = bytes.fromhex("8b19ac31d58b124c946209b5db1021b9")
		self.device_random = bytes.fromhex("55a2a2bca04cd32ff6f346bd0a0c1a3a")

	def test_link_open(self):
		uuid = UUID(hex="70cf7c9732a345b691494810d2e9cbf4")
		b = bytes.fromhex("23af5850000370cf7c9732a345b691494810d2e9cbf4")
		link_open = pb_generic.LinkOpenMessage(uuid)
		link_open.transaction_number = TransactionNumber.new(0)
		self.assertEqual(link_open.opcode, pb_generic.BearerControlOpcode.LinkOpen)
		self.assertEqual(link_open.opcode, 0x00)

		self.assertEqual(link_open.to_bytes(), b)
		self.assertEqual()


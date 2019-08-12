from applications.bluetooth_mesh.bt_mesh import crypto, mesh
import unittest


app_key = crypto.AppKey.from_int(0x3216d1509884b533248541792b877f98)
net_key = crypto.NetworkKey.from_int(0xf7a2a44f8e8a8029064f173ddc1e2b00)
dev_key = crypto.DeviceKey.from_int(0x37c612c4a2d337cb7b98355531b3617f)

class CryptoTests(unittest.TestCase):
	def test_s1(self):
		self.assertEqual(0xb73cefbd641ef2ea598c2b6efb62f79c.to_bytes(16, byteorder="big"), crypto.s1("test"))

	def test_k1(self):
		n = crypto.Key.from_int(0x3216d1509884b533248541792b877f98)
		salt = crypto.Salt(0x2ba14ffa0df84a2831938d57d276cab4.to_bytes(16, byteorder="big"))
		p = 0x5a09d60797eeb4478aada59db3352a0d.to_bytes(16, byteorder="big")
		self.assertEqual(0xf6ed15a8934afbe7d83e8dcb57fcf5d7.to_bytes(16, byteorder="big"), crypto.k1(salt, n, p))

	def test_k2_1(self):
		self.assertEqual((mesh.NID(0x73), crypto.EncryptionKey.from_int(0x11efec0642774992510fb5929646df49), crypto.PrivacyKey.from_int(0xd4d7cc0dfa772d836a8df9df5510d7a7)),
						 crypto.k2(net_key, 0x010203040506070809.to_bytes(9, byteorder="big")))

	def test_k2_2(self):
		self.assertEqual((mesh.NID(0x7F), crypto.EncryptionKey.from_int(0x9f589181a0f50de73c8070c7a6d27f46), crypto.PrivacyKey.from_int(0x4c715bd4a64b938f99b453351653124f)),
						 crypto.k2(net_key, b'\x00'))

	def test_k3(self):
		self.assertEqual(0xff046958233db014, crypto.k3(0xf7a2a44f8e8a8029064f173ddc1e2b00.to_bytes(16, byteorder="big")))

	def test_k4(self):
		self.assertEqual(mesh.NID(0x38), crypto.k4(0x3216d1509884b533248541792b877f98.to_bytes(16, byteorder="big")))

if __name__ == "__main__":
	unittest.main()
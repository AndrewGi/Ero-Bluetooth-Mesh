from .. import foundation, mesh
import unittest


class FoundationTest(unittest.TestCase):
	def test_composition_data_page0(self):
		# Sample data from Mesh Profile v1.0 Section 8.10 Composition Data sample data.
		# They seem to have a bug in the text "Features is 0x0003 – Relay and Friend features."
		# Relay and Friend features is 0x0005
		# Proxy and Relay features is 0x0003
		sample_data = bytes.fromhex("0C001A0001000800030000010501000000800100001003103F002A00")
		page0 = foundation.CompositionDataPage0(cid=foundation.CompanyID(0x000C), pid=foundation.ProductID(0x001A)
												, vid=foundation.VersionID(0x0001), crpl=foundation.CRPL(0x0008)
												, features=mesh.Features(mesh.Features.Relay | mesh.Features.Proxy)
												, elements=foundation.Elements(
				[foundation.ElementDescriptor(location=foundation.LocationDescriptor(0x0100)
											  , sig_models=[
						foundation.SIGModelID(0x0000), foundation.SIGModelID(0x8000)
						, foundation.SIGModelID(0x0001), foundation.SIGModelID(0x1000), foundation.SIGModelID(0x1003)
					], vendor_models=[
						foundation.VendorModelID(cid=foundation.CompanyID(0x003F),
												 model_id=foundation.access.ModelID(0x002A)),
					]), ]))
		self.assertEqual(page0.to_bytes(), sample_data)
		self.assertEqual(page0, foundation.CompositionDataPage0.from_bytes(sample_data))

	def test_log_field(self):
		# Sample data from Mesh Profile v1.0 Section 4.1.2 Log field transformations.

		lf = foundation.LogField
		self.assertEqual(lf(0x01).range(), (0x0001, 0x0001))
		self.assertEqual(lf(0x02).range(), (0x0002, 0x0003))
		self.assertEqual(lf(0x03).range(), (0x0004, 0x0007))
		self.assertEqual(lf(0x04).range(), (0x0008, 0x000F))
		self.assertEqual(lf(0x05).range(), (0x0010, 0x001F))
		self.assertEqual(lf(0x06).range(), (0x0020, 0x003F))
		self.assertEqual(lf(0x07).range(), (0x0040, 0x007F))
		self.assertEqual(lf(0x08).range(), (0x0080, 0x00FF))
		self.assertEqual(lf(0x09).range(), (0x0100, 0x01FF))
		self.assertEqual(lf(0x0A).range(), (0x0200, 0x03FF))
		self.assertEqual(lf(0x0B).range(), (0x0400, 0x07FF))
		self.assertEqual(lf(0x0C).range(), (0x0800, 0x0FFF))
		self.assertEqual(lf(0x0D).range(), (0x1000, 0x1FFF))
		self.assertEqual(lf(0x0E).range(), (0x2000, 0x3FFF))
		self.assertEqual(lf(0x0F).range(), (0x4000, 0x7FFF))
		self.assertEqual(lf(0x10).range(), (0x8000, 0xFFFF))

if __name__ == "__main__":
	unittest.main()

from applications.bluetooth_mesh.bt_mesh import foundation, mesh
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


if __name__ == "__main__":
	unittest.main()

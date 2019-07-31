import enum
from.pb_generic import GenericProvisioningPDU
LinkID = NewType("LinkID", int)
TransactionNumber = NewType("TransactionNumber", int)
class AdvPDU:
	__slots__ = "link_id", "transaction_number", "generic_prov_pdu"
	def __init__(self, link_id: LinkID, transaction_number: TransactionNumber, generic_prov_pdu: GenericProvisioningPDU):
		self.link_id = link_id
		self.transaction_number = transaction_number
		self.generic_prov_pdu = generic_prov_pdu

class Advertisement:
	__slots__ = "ad_type", "contents"
	def __init__(self):
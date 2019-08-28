import queue
import random
import struct
import threading
import time
from abc import ABC
from uuid import UUID
from typing import *
from .. import bearer, pb_generic, prov

LinkID = NewType("LinkID", int)


class AdvBearer(prov.ProvisionerBearer, bearer.Bearer, ABC):
	__slots__ = "ack_pb_adv", "recv_pb_adv"

	def __init__(self):
		super().__init__()
		self.ack_pb_adv: Optional[Callable[[], None]] = None
		self.recv_pb_adv: Optional[Callable[[bytes, ], None]] = None


	def send_pb_adv(self, pb_adv_pdu: bytes, repeat: Optional[bool] = False):
		raise NotImplementedError()

	def stop_adv(self):
		raise NotImplementedError()


class AdvPDU:
	STRUCT = struct.Struct("!LB")
	__slots__ = "link_id", "transaction_number", "generic_prov_pdu"

	def __init__(self, link_id: LinkID, transaction_number: prov.TransactionNumber,
				 generic_prov_pdu: pb_generic.GenericProvisioningPDU):
		self.link_id = link_id
		self.transaction_number = transaction_number
		self.generic_prov_pdu = generic_prov_pdu

	def to_bytes(self) -> bytes:
		return self.link_id.to_bytes(4, byteorder="big") + self.transaction_number.to_bytes(1,
																							byteorder="big") + self.generic_prov_pdu.to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'AdvPDU':
		link_id, transaction_number = cls.STRUCT.unpack(b[:cls.STRUCT.size])
		pdu = pb_generic.GenericProvisioningPDU.from_bytes(b[cls.STRUCT.size:])
		return cls(link_id, transaction_number, pdu)


class Link(prov.ProvisionerBearer):
	GENERIC_PROV_MTU = 24
	RETRANSMISSION_TRIES = 10
	RETRANSMISSION_DELAY = .25
	START_LINK_ID = LinkID(0x00000000)
	END_LINK_ID = LinkID(0xFFFFFFFF)

	@classmethod
	def mtu(cls) -> int:
		return cls.GENERIC_PROV_MTU

	@classmethod
	def set_link(cls, unprovisioned_device: prov.UnprovisionedDevice, adv_bearer: AdvBearer):
		unprovisioned_device.set_bearer(Link(cls.random_link_id(), unprovisioned_device.device_uuid))
		unprovisioned_device.pb_bearer.link_bearer = adv_bearer
		adv_bearer.recv_pb_adv = unprovisioned_device.pb_bearer.recv_pb_adv_pdu

	@classmethod
	def random_link_id(cls) -> LinkID:
		return LinkID(random.randint(cls.START_LINK_ID, cls.END_LINK_ID))

	def process_incoming_adv_pdu_worker(self):
		while True:
			item = self.incoming_adv_pdus.get()
			if not item:
				break
			self.handle_pb(item)
			self.incoming_adv_pdus.task_done()

	def __init__(self, link_id: LinkID, device_uuid: UUID):
		super().__init__()
		self.device_uuid = device_uuid
		self.link_id = link_id
		self.transaction_number = self.START_TRANSACTION_NUMBER
		self.link_bearer = None  # type: Optional[AdvBearer]
		self.is_open = False
		self.incoming_adv_pdus = queue.Queue()
		self.process_incoming_adv_pdus_thread = threading.Thread(target=self.process_incoming_adv_pdu_worker)
		self.process_incoming_adv_pdus_thread.start()
		self.link_ack_cv = threading.Condition()
		self.link_acked = False
		self.message_did_ack = False

	def increment_transaction_number(self):
		self.transaction_number = pb_generic.TransactionNumber(self.transaction_number + 1)
		if self.transaction_number > self.END_TRANSACTION_NUMBER:
			self.transaction_number = self.START_TRANSACTION_NUMBER

	def new_pdu(self, prov_pdu: pb_generic.GenericProvisioningPDU,
				transaction_number: Optional[prov.TransactionNumber] = None) -> AdvPDU:
		if prov_pdu is None:
			raise AttributeError("prov_pdu is none")
		if transaction_number is None:
			transaction_number = self.transaction_number
		out = AdvPDU(self.link_id, transaction_number, prov_pdu)
		return out

	def send_generic_prov_pdus(self, pdus: [pb_generic.GenericProvisioningPDU], retries: int = 3):
		out_pdus = [self.new_pdu(pdu, transaction_number=pdu.transaction_number) for pdu in pdus]
		link_ack = False
		trans_ack = False
		if out_pdus[0].generic_prov_pdu.gpcf() == pb_generic.GPCF.PROVISIONING_BEARER_CONTROL:
			link_ack = True
		if out_pdus[0].generic_prov_pdu.gpcf() == pb_generic.GPCF.TRANSACTION_START:
			trans_ack = True
		self.send_with_retries(out_pdus, retries, link_ack=link_ack, transaction_ack=trans_ack)

	def send_adv(self, pdu: AdvPDU, repeat: Optional[bool] = False):
		self.link_bearer.send_pb_adv(pdu.to_bytes(), repeat)

	def send_with_retries(self, pdus: List[AdvPDU], retries: int = None, link_ack: bool = False,
						  transaction_ack: bool = False):
		self.link_acked = False
		self.message_did_ack = False
		if not retries:
			retries = self.RETRANSMISSION_TRIES
		for i in range(retries):
			for pdu in pdus:
				self.send_adv(pdu)
			if link_ack:
				if self.link_acked:
					return True
				with self.link_ack_cv:
					if self.link_ack_cv.wait(self.RETRANSMISSION_DELAY):
						return True
			elif not transaction_ack:
				time.sleep(self.RETRANSMISSION_DELAY)
			elif (self.message_did_ack or self.wait_for_ack(self.RETRANSMISSION_DELAY)):
				return True
		self.is_open = False
		if (not transaction_ack) and (not link_ack):
			return
		raise TimeoutError("no ack")

	def open(self):
		if self.is_open:
			raise RuntimeError("link already open")
		pdu = self.new_pdu(pb_generic.LinkOpenMessage(self.device_uuid), transaction_number=0)
		self.is_open = self.send_with_retries([pdu], link_ack=True)

	def handle_link_ack(self, traction_number: prov.TransactionNumber, ack: pb_generic.TransactionAckPDU):
		print(self.link_acked)
		if self.link_acked:
			return
		if not self.is_open and traction_number == 0:
			self.is_open = True
		self.link_acked = True
		with self.link_ack_cv:
			self.link_ack_cv.notify_all()

	def handle_pb(self, adv_pdu: AdvPDU):
		gpcf = adv_pdu.generic_prov_pdu.gpcf()
		print(f"GPCF: {gpcf} trans#: {adv_pdu.transaction_number}")
		if gpcf == pb_generic.GPCF.PROVISIONING_BEARER_CONTROL:
			bearer_control = cast(pb_generic.BearerControlPDU, adv_pdu.generic_prov_pdu)
			opcode = bearer_control.opcode  # type: pb_generic.BearerControlOpcode
			if opcode == pb_generic.BearerControlOpcode.LinkACK:
				self.handle_link_ack(adv_pdu.transaction_number, cast(pb_generic.TransactionAckPDU, bearer_control.payload()))
		else:
			adv_pdu.generic_prov_pdu.transaction_number = adv_pdu.transaction_number
			self.recv_generic_prov_pdu(adv_pdu.generic_prov_pdu)

	def recv_pb_adv_pdu(self, incoming_pdu: bytes):
		pdu = AdvPDU.from_bytes(incoming_pdu)
		if pdu.link_id != self.link_id:
			# link id doesn't match this link
			return
		self.incoming_adv_pdus.put(pdu)

	def close(self, reason: pb_generic.LinkCloseReason):
		if not self.is_open:
			raise RuntimeError("link already close")
		self.send_adv(self.new_pdu(pb_generic.LinkCloseMessage(reason)))

	def link_ack(self, transaction_number: prov.TransactionNumber):
		self.send_adv(self.new_pdu(pb_generic.LinkAckMessage(), transaction_number=transaction_number))

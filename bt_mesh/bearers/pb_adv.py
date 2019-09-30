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
	MTU = 29  # maybe actually 27?
	STRUCT = struct.Struct("!LB")
	__slots__ = "link_id", "transaction_number", "generic_prov_pdu"

	def __init__(self, link_id: LinkID, transaction_number: prov.mesh.TransactionNumber,
				 generic_prov_pdu: pb_generic.GenericProvisioningPDU):
		self.link_id = link_id
		self.transaction_number = transaction_number
		self.generic_prov_pdu = generic_prov_pdu

	def to_bytes(self) -> bytes:
		b = self.link_id.to_bytes(4,
								  byteorder="big") + self.transaction_number.to_bytes() + self.generic_prov_pdu.to_bytes()
		if len(b) > self.MTU:
			raise ValueError(f"adv mtu {self.MTU} > {len(b)}")
		return b

	@classmethod
	def from_bytes(cls, b: bytes) -> 'AdvPDU':
		link_id, transaction_number = cls.STRUCT.unpack(b[:cls.STRUCT.size])
		pdu = pb_generic.GenericProvisioningPDU.from_bytes(b[cls.STRUCT.size:])
		return cls(LinkID(link_id), prov.mesh.TransactionNumber(transaction_number), pdu)


class Links:
	__slots__ = "links", "link_bearer"

	def __init__(self, link_bearer: AdvBearer) -> None:
		self.links: Dict[LinkID, Link] = dict()
		self.link_bearer = link_bearer
		self.link_bearer.recv_pb_adv = self.recv_pb_adv

	def close_link(self, link_id: LinkID) -> None:
		del self.links[link_id]

	def send_pb_adv(self, pdu: bytes, repeat: bool) -> None:
		self.link_bearer.send_pb_adv(pdu, repeat)

	def recv_pb_adv(self, raw_pdu: bytes) -> None:
		adv_pdu = AdvPDU.from_bytes(raw_pdu)
		link_id = adv_pdu.link_id
		try:
			self.links[link_id].incoming_adv_pdus.put(adv_pdu)
		except KeyError:
			# link id is not in collection
			pass

	def new_link(self, device_uuid: UUID) -> 'Link':
		"""
		Generates a new link for a given device UUID.

		:param device_uuid:
		:return: An unopened link with a random link id
		"""
		assert len(self.links) < Link.END_LINK_ID / 4, "sanity check for link leak"
		current_link_ids = self.links.keys()
		new_id = Link.random_link_id()
		while new_id in current_link_ids:
			new_id = Link.random_link_id()
		link = Link(new_id, device_uuid)
		self.links[new_id] = link
		link.send_pb_adv = self.send_pb_adv
		return link


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
		cast(Link, unprovisioned_device.pb_bearer).send_pb_adv = adv_bearer.send_pb_adv
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
		self.send_pb_adv: Optional[Callable[[bytes, bool], None]] = None
		self.is_open = False
		self.accept_incoming = True
		self.incoming_adv_pdus = queue.Queue()
		self.process_incoming_adv_pdus_thread = threading.Thread(target=self.process_incoming_adv_pdu_worker)
		self.process_incoming_adv_pdus_thread.start()
		self.link_ack_cv = threading.Condition()
		self.link_acked = False
		self.message_did_ack = False

	def increment_transaction_number(self):
		self.transaction_number = prov.mesh.TransactionNumber(self.transaction_number + 1)
		if self.transaction_number > self.END_TRANSACTION_NUMBER:
			self.transaction_number = self.START_TRANSACTION_NUMBER

	def new_pdu(self, prov_pdu: pb_generic.GenericProvisioningPDU,
				transaction_number: Optional[prov.mesh.TransactionNumber] = None) -> AdvPDU:
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
		if not self.send_pb_adv:
			raise ValueError("missing send_pb_adv")
		self.send_pb_adv(pdu.to_bytes(), repeat)

	def send_with_retries(self, pdus: List[AdvPDU], retries: int = None, link_ack: bool = False,
						  transaction_ack: bool = False):
		self.link_acked = False
		self.message_did_ack = False
		if not retries:
			retries = self.RETRANSMISSION_TRIES
		for i in range(retries):
			for pdu in pdus:
				if self.closed():
					return # Link closed
				self.send_adv(pdu)
			if link_ack:
				if self.link_acked:
					return
				with self.link_ack_cv:
					if self.link_ack_cv.wait(self.RETRANSMISSION_DELAY):
						return
			elif not transaction_ack:
				time.sleep(self.RETRANSMISSION_DELAY)
			elif self.message_did_ack or self.wait_for_ack(self.RETRANSMISSION_DELAY):
				return
		self.is_open = False
		if (not transaction_ack) and (not link_ack):
			return
		raise TimeoutError("no ack")

	def open(self):
		if self.is_open:
			raise RuntimeError("link already open")
		if self.closed():
			raise RuntimeError("link can't be reopened")
		pdu = self.new_pdu(pb_generic.LinkOpenMessage(self.device_uuid),
						   transaction_number=prov.mesh.TransactionNumber(0))
		self.send_with_retries([pdu], link_ack=True)

	def handle_link_ack(self, traction_number: prov.mesh.TransactionNumber, ack: pb_generic.TransactionAckPDU):
		if self.closed():
			return
		del ack  # we don't use the message
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
			opcode: pb_generic.BearerControlOpcode = bearer_control.opcode
			if opcode == pb_generic.BearerControlOpcode.LinkACK:
				self.handle_link_ack(adv_pdu.transaction_number,
									 cast(pb_generic.TransactionAckPDU, bearer_control.payload()))
		else:
			adv_pdu.generic_prov_pdu.transaction_number = adv_pdu.transaction_number
			self.recv_generic_prov_pdu(adv_pdu.generic_prov_pdu)

	def recv_pb_adv_pdu(self, incoming_pdu: bytes):
		if self.closed():
			# link closed
			return
		pdu = AdvPDU.from_bytes(incoming_pdu)
		if pdu.link_id != self.link_id:
			# link id doesn't match this link
			return
		self.incoming_adv_pdus.put(pdu)

	def closed(self) -> bool:
		return not self.accept_incoming

	def close(self, reason: pb_generic.LinkCloseReason):
		if self.closed():
			raise RuntimeError("link already close")
		self.send_adv(self.new_pdu(pb_generic.LinkCloseMessage(reason)))
		self.is_open = False
		self.accept_incoming = False

	def link_ack(self, transaction_number: prov.mesh.TransactionNumber):
		self.send_adv(self.new_pdu(pb_generic.LinkAckMessage(), transaction_number=transaction_number))

	def __del__(self):
		if not self.closed():
			self.close(pb_generic.LinkCloseReason.Fail)

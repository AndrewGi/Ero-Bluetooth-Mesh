import enum
from abc import ABC, abstractmethod
from typing import Generator, Iterator, Optional
from . import bearer, beacon, mesh


class MessageType(enum.IntEnum):
	NetworkPDU = 0x00
	MeshBeacon = 0x01
	ProxyConfiguration = 0x02
	ProvisioningPDU = 0x03


class SARFlag(enum.IntEnum):
	Complete = 0b00
	First = 0b01
	Continue = 0b10
	Last = 0b11


class PDU:
	__slots__ = "sar", "message_type", "data"

	def __init__(self, sar: SARFlag, message_type: MessageType, data: bytes):
		self.sar = sar
		self.message_type = message_type
		self.data = data

	@classmethod
	def from_bytes(cls, b: bytes) -> 'PDU':
		sar = SARFlag((b[0] & 0xC0) >> 6)
		msg_type = MessageType(b[0] & 0x3F)
		return cls(sar, msg_type, b[1:])

	def to_bytes(self) -> bytes:
		return bytes([((self.sar & 0x03) << 6) | (self.message_type & 0x3F)]) + self.data


class SARAssembler:
	__slots__ = "data", "message_type", "is_done"

	def __init__(self, first_pdu: PDU):
		if first_pdu.sar == SARFlag.Continue or first_pdu.sar.Last:
			raise ValueError(f"invalid first pdu flag {first_pdu.sar}")
		self.data = bytearray(first_pdu.data)
		self.message_type = first_pdu.message_type
		self.is_done = first_pdu.sar == SARFlag.Complete

	def ready(self) -> bool:
		return self.is_done

	def pop(self) -> PDU:
		if not self.ready():
			raise ValueError("assembler not ready yet")
		return PDU(SARFlag.Complete, self.message_type, bytes(self.data))

	def incoming_packet(self, pdu: PDU) -> bool:
		if self.ready():
			raise ValueError("assembler already ready")
		if pdu.message_type != self.message_type:
			raise ValueError(f"conflicting message type {self.message_type}!={pdu.message_type}")
		if pdu.sar == SARFlag.First or pdu.sar.Complete:
			raise ValueError(f"expected continue or last SAR got {pdu.sar}")
		self.data += pdu.data
		self.is_done = pdu.sar == SARFlag.Last
		return self.ready()


def segment_pdu(message_type: MessageType, mtu: int, data: bytes) -> Generator[PDU, None, PDU]:
	if len(data) - 1 <= mtu:
		return PDU(SARFlag.Complete, message_type, data)
	chunk_size = mtu - 1  # - 1 for the SAR and Message Type
	position = 0
	yield PDU(SARFlag.First, message_type, data[:chunk_size])
	position += chunk_size
	while (position + chunk_size) < len(data):
		yield PDU(SARFlag.Continue, message_type, data[position:position + chunk_size])
	return PDU(SARFlag.Last, message_type, data[position:])


class ProxyBearer(bearer.Bearer, ABC):
	__slots__ = "sar_assembler", "transmit_parameters"

	def __init__(self):
		super().__init__(None)
		self.sar_assembler: Optional[SARAssembler] = None
		self.transmit_parameters: mesh.TransmitParameters = mesh.TransmitParameters.default()

	@classmethod
	def bearer_type(cls):
		return bearer.BearerType.Proxy

	@abstractmethod
	def proxy_mtu(self) -> int:
		raise NotImplementedError()

	def send_proxy_pdus(self, pdus: Iterator):
		for pdu in pdus:
			self.send_proxy_pdu(pdu)

	def send_beacon(self, in_beacon: beacon.Beacon):
		self.send_proxy_pdus(segment_pdu(MessageType.MeshBeacon, self.proxy_mtu(), in_beacon.to_bytes()))

	def send_network_pdu(self, network_pdu: bytes):
		self.send_proxy_pdus(segment_pdu(MessageType.NetworkPDU, self.proxy_mtu(), network_pdu))

	@abstractmethod
	def send_proxy_pdu(self, pdu: PDU):
		raise NotImplementedError()

	def handle_complete_pdu(self, pdu: PDU):
		if pdu.sar != SARFlag.Complete:
			raise ValueError("unexpected non-complete PDU")
		if pdu.message_type == MessageType.NetworkPDU:
			self.recv_network_pdu(pdu.data)
		elif pdu.message_type == MessageType.MeshBeacon:
			self.recv_beacon(beacon.Beacon.from_bytes(pdu.data))
		else:
			raise NotImplementedError(f"unhandled proxy pdu type: {pdu.message_type}")

	def recv_proxy_pdu(self, pdu: PDU):
		if not self.sar_assembler:
			self.sar_assembler = SARAssembler(pdu)
		else:
			self.sar_assembler.incoming_packet(pdu)

		if self.sar_assembler.ready():
			complete_pdu = self.sar_assembler.pop()
			self.sar_assembler = None
			self.handle_complete_pdu(complete_pdu)


class ProxyServer(ProxyBearer, ABC):
	__slots__ = "mesh_bearer",

	def recv_beacon(self, mesh_beacon_payload: beacon.Beacon):
		if self.mesh_bearer:
			self.mesh_bearer.send_beacon(mesh_beacon_payload)

	def recv_network_pdu(self, network_pdu: bytes):
		if self.mesh_bearer:
			self.mesh_bearer.send_network_pdu(network_pdu, se)

	def __init__(self, mesh_bearer: bearer.Bearer):
		super().__init__()
		self.mesh_bearer = mesh_bearer
		self.set_bearer(mesh_bearer)

	def set_bearer(self, mesh_bearer):
		if not mesh_bearer:
			return
		self.mesh_bearer = mesh_bearer
		self.mesh_bearer.recv_beacon = self.send_beacon
		self.mesh_bearer.recv_network_pdu = self.send_network_pdu


class ProxyClient(ProxyBearer, ABC):
	pass

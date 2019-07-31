import datetime
import socketserver
import struct
import atexit
from .. import ero_bluetooth_mesh
from ..ero_bluetooth_mesh import Address, UnicastAddress, GroupAddress, NetworkID, SubnetHandle, AppkeyHandle
from typing import *
from uuid import UUID
import uuid
import time
import ssl
import threading
import ipaddress
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from ero import ero_log
import socket
import os

HOSTNAME = "network.dev.tapjac.tech"
CERT_FILE = "certs/network.dev.tapjac.tech.crt"
PRIVATE_KEY_FILE = "certs/privkey.pem"
PORT = 17737

btm_app = None
logger = None


def mesh_app() -> ero_bluetooth_mesh.BluetoothMeshApplication:
	global btm_app
	assert btm_app is not None
	return btm_app


def crc16(data: bytes, poly: int = 0x1021) -> int:
	'''
	CRC-16-CCITT Algorithm
	'''
	if not data:
		return 0
	data = bytearray(data)
	crc = 0xFFFF
	for b in data:
		cur_byte = 0xFF & b
		for _ in range(0, 8):
			if (crc & 0x0001) ^ (cur_byte & 0x0001):
				crc = (crc >> 1) ^ poly
			else:
				crc >>= 1
			cur_byte >>= 1
	crc = (~crc & 0xFFFF)
	crc = (crc << 8) | ((crc >> 8) & 0xFF)

	return crc & 0xFFFF


Opcode = NewType("Opcode", int)


class Packet:
	def __init__(self, opcode: Opcode, data: bytes):
		self.opcode = opcode
		self.data = data


class Message:
	message_to_opcode = dict()  # type: Dict[Type[Message], Opcode]
	opcode_to_message = dict()  # type: Dict[Opcode, Tuple[Type[Message], Callable]]

	@classmethod
	def add_message_type(cls, message: Type, opcode: Opcode, handler: Callable):
		assert issubclass(message, Message)
		cls.message_to_opcode[message] = opcode
		cls.opcode_to_message[opcode] = (message, handler)

	@classmethod
	def decode_packet(cls, packet: Packet):
		cls.opcode_to_message[packet.opcode].from_bytes(packet.data)

	@classmethod
	def get_message_handler(cls):
		return cls.opcode_to_message[cls.message_to_opcode[cls]]

	@classmethod
	def from_bytes(cls, b: bytes):
		raise NotImplementedError()

	def to_bytes(self) -> bytes:
		raise NotImplementedError()

	def to_packet(self) -> Packet:
		return Packet(self.get_opcode(), self.to_bytes())

	def get_opcode(cls) -> Opcode:
		return cls.message_to_opcode[cls]


class Ping(Message):
	@classmethod
	def from_bytes(cls, b: bytes):
		return Ping()

	def to_bytes(self) -> bytes:
		return b""

	def get_opcode(cls) -> Opcode:
		return Opcode(0x00)

class Pong(Message):
	@classmethod
	def from_bytes(cls, b: bytes):
		assert len(b) == 0
		return cls()

	def to_bytes(self) -> bytes:
		return b""

	@classmethod
	def get_opcode(cls) -> Opcode:
		return Opcode(0x01)


class Status(Message):
	fmt = struct.Struct("<16sQQLH")

	def __init__(self, version: int, kernel_version: int, uptime: int, unix_time: int, uuid: UUID):
		self.version = version
		self.kernel_version = kernel_version
		self.uptime = uptime
		self.unix_time = unix_time
		self.uuid = uuid

	@classmethod
	def from_bytes(cls, b: bytes):
		uuid, uptime, unix_time, kernel_version, version = cls.fmt.unpack(b)
		return cls(version, kernel_version, uptime, unix_time, UUID(bytes=uuid))

	def to_bytes(self) -> bytes:
		return self.fmt.pack(self.version, self.kernel_version, self.uptime, self.unix_time, self.uptime)

	@classmethod
	def get_opcode(cls) -> Opcode:
		return Opcode(0x02)


class ServerStatus(Message):

	@classmethod
	def from_bytes(cls, b: bytes):
		pass

	def to_bytes(self) -> bytes:
		# TODO: double check get_bytes order
		struct.pack("16sQ", self.connection_uuid.bytes_le, self.server_time)

	def __init__(self, connection_uuid: UUID, server_time: int):
		self.connection_uuid = connection_uuid
		self.server_time = server_time

	def get_opcode(cls) -> Opcode:
		return Status.get_opcode()

class AskStatus(Message):

	@classmethod
	def from_bytes(cls, b: bytes):
		assert len(b) == 0
		return cls

	def to_bytes(self) -> bytes:
		return b""


class MeshMessage(Message):
	fmt = struct.Struct("<QHHHHBB")

	def __init__(self, occurrence_time: int, src: int, dst: int, subnet_handle: int, appkey_handle: int, ttl: int,
				 rssi: int, data: bytes):
		self.occurrence_time = occurrence_time
		self.src = src
		self.dst = dst
		self.subnet_handle = subnet_handle
		self.appkey_handle = appkey_handle
		self.ttl = ttl
		self.rssi = rssi
		self.data = data

	@classmethod
	def from_bytes(cls, b: bytes):
		src, dst, subnet_handle, appkey_handle, ttl, rssi = cls.fmt.unpack(b[:cls.fmt.size])
		data = b[cls.fmt.size:]
		return cls(src, dst, subnet_handle, appkey_handle, ttl, rssi, data)

	def to_bytes(self) -> bytes:
		return self.fmt.pack(self.src, self.dst, self.subnet_handle, self.appkey_handle, self.ttl,
							 self.rssi) + self.data

	def to_btm_message(self, network_id: ero_bluetooth_mesh.NetworkID) -> ero_bluetooth_mesh.Message:
		return ero_bluetooth_mesh.Message(network_id=network_id, src=UnicastAddress(self.src),
										  dst=Address(self.dst), subnet_handle=SubnetHandle(self.subnet_handle),
										  appkey_handle=self.appkey_handle, data=self.data, rssi=self.rssi,
										  ttl=self.ttl)

	@classmethod
	def from_router_message(cls, msg: ero_bluetooth_mesh.Router.RouterMeshMessage):
		return cls(occurrence_time=int(time.time()), src=msg.src, dst=msg.dst, subnet_handle=msg.subnet_handle,
				   appkey_handle=msg.appkey_handle, ttl=msg.ttl, rssi=0, data=msg.data)


class Administration(Message):
	AdminOpcode = NewType("AdminOpcode", int)

	ACK = AdminOpcode(0)
	LOGIN = AdminOpcode(1)
	REGISTER = AdminOpcode(2)
	IPCONFIG = AdminOpcode(3)

	class Ack(Message):

		@classmethod
		def from_bytes(cls, b: bytes):
			return cls()

		def to_bytes(self) -> bytes:
			return bytes()

	class ConnectRequest(Message):

		def __init__(self, time: int):
			pass

	class RegisterRequest(Message):
		@classmethod
		def from_bytes(cls, b: bytes):
			return cls(Status.from_bytes(b))

		def to_bytes(self) -> bytes:
			return self.status.to_bytes()

		def __init__(self, status: Status):
			self.status = status

	class RegisterResponse(Message):

		def __init__(self, register_opcode: Opcode):
			self.register_opcode = register_opcode

		@classmethod
		def from_bytes(cls, b: bytes):
			pass

		def to_bytes(self) -> bytes:
			pass

	class IPConfigRequest(Message):
		@classmethod
		def from_bytes(cls, b: bytes):
			return cls()

		def to_bytes(self) -> bytes:
			return bytes()

	class IPConfigResponse(Message):

		def __init__(self, local: ipaddress.IPv4Network):
			pass


class Provision:
	ProvisionOpcode = NewType("ProvisionOpcode", int)

	DISCOVERED_UNPROVISIONED = ProvisionOpcode(0)
	PROVISION = ProvisionOpcode(1)

	class DiscoveredUnprovisioned(Message):

		def __init__(self, uuid: UUID, oob_data: int, uri_hash: int, rssi: int):
			self.uuid = uuid
			self.oob_data = oob_data
			self.uri_hash = uri_hash
			self.rssi = rssi

		@classmethod
		def from_bytes(cls, b: bytes):
			pass

		def to_bytes(self) -> bytes:
			pass

	class ProvisionRequest(Message):

		@classmethod
		def from_bytes(cls, b: bytes):
			return cls(UUID(bytes=b[0:16]))

		def to_bytes(self) -> bytes:
			return self.uuid.bytes_le

		def __init__(self, uuid: UUID):
			self.uuid = uuid

	class ProvisionResponse(Message):
		pass


class SocketRouterHandler(ero_bluetooth_mesh.Router):
	SEQ = b'\xFE\x02'
	ENDIAN = "little"

	def __init__(self, request: ssl.SSLSocket, client_address: socket.AddressInfo, server: ssl.SSLSocket):
		super().__init__(ero_bluetooth_mesh.UnregisteredDevice)
		self.request = request
		self.client_address = client_address
		self.server = server
		self.connected = True
		self.last_status = None  # type: Status
		self.write_lock = threading.Lock()
		self.connection_uuid = uuid.uuid4()
		self.request.settimeout(2)
		self.ping_start_time = 0.0
		self.ping_pong_time = 0.0
		self.serial_number = self.request.getpeercert()["serialNumber"]

	def _recv(self, size: int) -> bytes:
		if size == 0:
			return bytes()
		b = bytes()
		while True:
			b += self.request.recv(size)
			if len(b) == size:
				break
		return b

	def _send(self, b: bytes):
		assert len(b) != 0
		self.request.send(b)

	def _read_unsigned(self, byte_size: int) -> int:
		if byte_size <= 0:
			raise ValueError("requested negative/0 bytes")
		b = self._recv(byte_size)
		return int.from_bytes(b, byteorder=self.ENDIAN)

	def _get_length(self) -> int:
		return self._read_unsigned(2)  # length is uint16_t

	def _get_opcode(self) -> int:
		return self._read_unsigned(2)  # opcode is uint16_t

	def _get_content(self, length: int) -> bytes:
		return self._recv(length)

	def _get_crc(self) -> int:
		return self._read_unsigned(2)

	def _wait_for_start_sequence(self):
		while self.connected:
			try:
				while self._recv(1)[0] != self.SEQ[0]:
					pass

				if self._recv(1)[0] == self.SEQ[1]:
					break
				else:
					continue
			except socket.timeout:
				# timeout while waiting for start sequence
				pass

	@staticmethod
	def _decode_packet(packet: Packet) -> Message:
		return Message.opcode_to_message[packet.opcode][0].from_bytes(packet.data)

	def get_packet(self):
		self._wait_for_start_sequence()
		opcode = self._get_opcode()
		length = self._get_length()
		data = self._get_content(length)
		return Packet(opcode, data)

	def send_packet(self, packet: Packet):
		def send_u16(i: int):
			self._send(struct.pack("<H", i))

		if not self.write_lock.acquire(timeout=2):
			raise TimeoutError("timeout trying to acquire lock write")
		try:
			self._send(self.SEQ)  # START SEQ
			send_u16(len(packet.data) if packet.data else 0)
			send_u16(packet.opcode)
			if packet.data:
				self._send(packet.data)
		finally:
			self.write_lock.release()

	def handle_packet(self, packet: Packet):
		message = self._decode_packet(packet)
		t, handler = message.get_message_handler()
		handler(message, self)

	def _log_prefix(self):
		uuid = self.router.uuid if hasattr(self, "router") else None
		return f"{f'[{uuid}]' if uuid is not None else ''}[{self.client_address}]"

	def finish(self):
		self.connected = False
		logger.info(f"{self._log_prefix()} disconnected")

	def send_ping(self):
		out_packet = Ping().to_packet()
		self.ping_start_time = time.time()
		self.ping_pong_time = 0
		self.send_packet(out_packet)
		logger.info(f"{self._log_prefix()} ping sent")

	def handle_pong(self):
		self.ping_pong_time = time.time() - self.ping_start_time
		logger.debug(f"{self._log_prefix()} {int(self.ping_pong_time*1000)}ms pong time")
		self.report_pong(int(self.ping_pong_time*1000*1000))

	def handle(self):
		print(self.request.getpeercert()["serialNumber"])
		logger.info(f"{self._log_prefix()} connected")
		self.ping()
		assert self.get_packet().opcode == Pong.get_opcode(), "expected pong as first packet"
		self.handle_pong()
		while self.connected:
			packet = self.get_packet()
			logger.debug(f"{self._log_prefix()} handling packet opcode: {packet.opcode}")
			self.handle_packet(packet)


class SocketRouterServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	pass


def start(app: ero_bluetooth_mesh.BluetoothMeshApplication):
	global btm_app, logger
	assert btm_app is None
	assert logger is None
	Message.add_message_type(Ping, 0x00, ping_handler)
	Message.add_message_type(Pong, 0x01, pong_handler)
	Message.add_message_type(Status, 0x02, status_handler)
	Message.add_message_type(AskStatus, 0x03, ask_status_handler)
	Message.add_message_type(MeshMessage, 0x04, mesh_message_handler)
	Message.add_message_type(Administration, 0x05, administration_handler)
	Message.add_message_type(Provision.ProvisionRequest, 0x06, provision_handler)
	btm_app = app
	logger = ero_log.setup_app_logger("btm_socket_router")
	_router_threads = list() # type: List[threading.Thread]
	def _close_routers():
		logger.info("shutting down router socket connections...")
		for thread in _router_threads:
			thread.join()
		logger.info("shutdown router socket connection!")

	atexit.register(_close_routers)
	def handle_request(request: ssl.SSLSocket, address: socket.AddressInfo, server: ssl.SSLSocket):
				router = SocketRouterHandler(request, address, server)
				thread = threading.Thread(target=router.handle)
				_router_threads.append(thread)
				thread.start()

	print(os.getcwd())
	ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
	ssl_context.load_cert_chain(CERT_FILE, PRIVATE_KEY_FILE)
	ssl_context.load_verify_locations("certs/ca/dev_ca_certificate.crt")
	ssl_context.verify_mode = ssl.CERT_REQUIRED
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind(("0.0.0.0", PORT))
		sock.listen(20) # TODO: increase maybe?

		with ssl_context.wrap_socket(sock, server_hostname=HOSTNAME) as ssock:
			while True:
				conn, addr = ssock.accept()
				handle_request(conn, addr, ssock)




def ping_handler(msg: Ping, socket_handler: SocketRouterHandler):
	socket_handler.server_pinged()
	socket_handler.send_packet(Pong().to_packet())


def pong_handler(msg: Pong, socket_handler: SocketRouterHandler):
	socket_handler.handle_pong()

def status_handler(msg: Status, socket_handler: SocketRouterHandler):
	socket_handler.last_status = msg


def ask_status_handler(msg: AskStatus, socket_handler: SocketRouterHandler):
	logger.debug(f"{socket_handler._log_prefix()} server status asked")
	socket_handler.send_packet(ServerStatus(socket_handler.connection_uuid, int(time.time() * 1000)).to_packet())


def mesh_message_handler(msg: MeshMessage, socket_handler: SocketRouterHandler):
	socket_handler.receive_message(datetime.datetime.fromtimestamp(msg.occurrence_time), msg.to_btm_message(socket_handler.network_id))


def administration_handler(msg: Administration, socket_handler: SocketRouterHandler):
	pass


def provision_handler(msg: Provision.ProvisionRequest, socket_handler: SocketRouterHandler):
	pass


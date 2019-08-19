import socket
import threading
import ssl
import enum
from typing import *
from applications.bluetooth_mesh.bt_mesh.proxy import PDU
from .. import proxy, bearer

MAGIC_NUMBER: int = 0x37
INVERT_MAGIC_NUMBER: int = (~MAGIC_NUMBER) & 0xFF
MAGIC_START_SEQ: bytes = bytes([MAGIC_NUMBER, INVERT_MAGIC_NUMBER])


class ProxyMessageType(enum.IntEnum):
	PROXY_PDU = 0x01
	CUSTOM_PDU_START = 0x3F # reserved for the user


class SocketProxyPipe:
	def __init__(self, secure_socket: ssl.SSLSocket):
		self.sock: ssl.SSLSocket = secure_socket
		self.is_open: bool = True
		self.read_lock: threading.Lock = threading.Lock()
		self.write_lock: threading.Lock = threading.Lock()

	def __del__(self):
		self.sock.close()

	def _recv(self, amount: int, timeout: bool = True) -> bytearray:
		if amount <= 0:
			raise ValueError(f"amount too low {amount}<=0")
		out = bytearray()
		with self.read_lock:
			while amount:
				try:
					tmp = self.sock.recv(amount)
					amount -= len(tmp)
					out += tmp
				except TimeoutError as e:
					if timeout:
						raise e
					else:
						pass
			return out

	def _send(self, data: bytes):
		position = 0
		with self.write_lock:
			while position < len(data):
				sent = self.sock.send(data[position:])
				assert sent > 0, "unable to send socket data"
				position += sent

	def wait_for_double_magic(self):
		while True:
			while self._recv(1, timeout=False)[0] != MAGIC_NUMBER:
				pass
			if self._recv(1, timeout=False)[0] == INVERT_MAGIC_NUMBER:
				break

	def read_proxy_pdu(self) -> proxy.PDU:
		self.wait_for_double_magic()
		message_type = ProxyMessageType(int.from_bytes(self._recv(1), byteorder="big"))
		assert message_type == ProxyMessageType.PROXY_PDU
		len_message = int.from_bytes(self._recv(2), byteorder="big")
		msg = self._recv(len_message)
		return proxy.PDU.from_bytes(msg)

	def send_proxy_pdu(self, pdu: proxy.PDU):
		pdu_bytes = pdu.to_bytes()
		len_bytes = len(pdu_bytes).to_bytes(2, byteorder="big")
		self._send(MAGIC_START_SEQ + ProxyMessageType.PROXY_PDU.to_bytes(1, "big") + len_bytes + pdu_bytes)


class SocketProxyServer(proxy.ProxyServer):
	__slots__ = "pipe",

	def __init__(self, pipe: SocketProxyPipe, out_bearer: bearer.Bearer):
		super().__init__(out_bearer)
		self.pipe = pipe
		self.read_loop_thread = threading.Thread(target=self.read_loop)
		self.read_loop_thread.start()

	def proxy_mtu(self) -> int:
		return 1024

	def send_proxy_pdu(self, pdu: PDU):
		self.pipe.send_proxy_pdu(pdu)

	def read_loop(self):
		while self.pipe.is_open:
			pdu = self.pipe.read_proxy_pdu()
			self.recv_proxy_pdu(pdu)


class SocketProxyClient(proxy.ProxyClient):
	def __init__(self, pipe: SocketProxyPipe):
		super().__init__()
		self.pipe = pipe
		self.read_loop_thread = threading.Thread(target=self.read_loop)
		self.read_loop_thread.start()

	def proxy_mtu(self) -> int:
		return 1024

	def send_proxy_pdu(self, pdu: PDU):
		self.pipe.send_proxy_pdu(pdu)

	def read_loop(self):
		while self.pipe.is_open:
			pdu = self.pipe.read_proxy_pdu()
			self.recv_proxy_pdu(pdu)


class SocketPipeServer:
	def __init__(self, ssl_context: ssl.SSLContext, port: int):
		ssl_context.verify_mode = ssl.CERT_REQUIRED
		self.ssl_context = ssl_context
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
		self.port = port
		self.sock.bind(("", port))
		self.sock.listen(10)
		self.worker_thread = threading.Thread(target=self.worker_func)

	def start(self):
		if self.worker_thread.is_alive():
			raise ValueError("worker thread already alive")
		self.worker_thread.start()

	def worker_func(self):
		with self.ssl_context.wrap_socket(self.sock, server_side=True) as ssock:
			conn, addr = ssock.accept()
			self.handle_pipe(SocketProxyPipe(conn))

	def handle_pipe(self, pipe: SocketProxyPipe):
		raise NotImplementedError()


def connect_pipe(hostname: str, port: int, ssl_context: ssl.SSLContext) -> SocketProxyPipe:
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	ssock = ssl_context.wrap_socket(sock, server_hostname=hostname)
	ssock.connect((hostname, port))
	return SocketProxyPipe(ssock)

import socket, fcntl, array
from . import hci, hci_interface

HCI_DEV_UP = 0x400448c9
HCI_DEV_DOWN = 0x400448ca
HCI_GET_DEV_INFO = 0x7ffbb72d
HCI_SET_SCAN = 0x400448dd

HCI_COMMAND_PKT = 0x01
HCI_ACLDATA_PKT = 0x02
HCI_EVENT_PKT = 0x04


class SocketInterface(hci_interface.Interface):
	def __init__(self, device_id: int) -> None:
		super().__init__()
		self.device_id = device_id
		self.sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
		self.sock.bind((self.device_id,))
		self.keep_running = True

	def handle_data(self, b: bytes) -> None:
		pass

	def _socket_worker(self) -> None:
		while self.keep_running:
			self.handle_data(self.sock.recv(1024))

	def close(self) -> None:
		assert self.keep_running
		self.keep_running = False
		self.sock.close()

	def is_open(self) -> bool:
		return self.keep_running

	def send_cmd(self, cmd: int, data: bytes) -> array.ArrayType:
		arr = array.array('B', data)
		fcntl.ioctl(self.sock.fileno(), cmd, arr)
		return arr

	def send_buffer(self, buffer: bytes) -> None:
		self.sock.send(buffer)

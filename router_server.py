from .bt_mesh import bearer

class RouterServer(bearer.Bearer):
	def send(self, network_pdu: bytes):
		pass

	def recv(self, network_pdu: bytes):
		pass
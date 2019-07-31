from applications.bluetooth_mesh.ero_bluetooth_mesh import Message
from applications.bluetooth_mesh import ero_bluetooth_mesh


class WebSocketRouter(ero_bluetooth_mesh.Router):
	def send_message(self, message: Message):
		pass
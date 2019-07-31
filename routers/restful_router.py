from applications.bluetooth_mesh.ero_bluetooth_mesh import Message
from applications.bluetooth_mesh import ero_bluetooth_mesh
import flask
import datetime
import json
import threading
from typing import *
restful_router_bp = flask.Blueprint("restful_router", __name__)


LOCK_TIMEOUT = 2
class RESTfulRouter(ero_bluetooth_mesh.Router):
	def __init__(self):
		self.output_lock = threading.Lock()
		self.output_buffer = list() #type: List[str]

	def _append_to_buffer(self, dict: Dict[Any, Any]):
		json_payload = json.dumps(dict)
		if not self.output_lock.acquire(timeout=LOCK_TIMEOUT):
			raise TimeoutError("append output lock timeout")
		try:
			self.output_buffer.append(json_payload)
		finally:
			self.output_lock.release()


	def dump_output_buffer(self):
		if not self.output_lock.acquire(timeout=LOCK_TIMEOUT):
			raise TimeoutError("empty output lock timeout")
		try:
			buffer = self.output_buffer
			self.output_buffer = list()
			return buffer
		finally:
			self.output_lock.release()

	def send_message(self, message: Message):
		self._append_to_buffer(message.as_dict())


@restful_router_bp.route("unregistered")
def unregistered_wp():
	return "test"

@restful_router_bp.route("")

@restful_router_bp.route("live_events")
def live_events
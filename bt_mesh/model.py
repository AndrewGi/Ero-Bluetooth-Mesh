from abc import ABC

from .mesh import *
from . import access
from .access import ModelID
class Model:
	__slots__ = "company_id", "model_id"
	def __init__(self, model_id: ModelID, company_id: Optional[CompanyID] = SIGCompanyID) -> None:
		self.model_id = model_id
		self.company_id = company_id


class ModelServer:
	pass

class ModelClient:
	def publish(self, msg: access.AccessMessage):


class ModelMessage(ByteSerializable, ABC):
	pass

class UnknownOpcode(Exception):
	pass

class State:
	__slots__ = "handlers",
	def __init__(self):
		self.handlers: Dict[access.Opcode, Callable]

	def add_handler(self, opcode: access.Opcode, handler: Callable) -> None:
		if opcode in self.handlers.values():
			raise ValueError(f"handlers already handling f{str(opcode)}")
		self.handlers[opcode] = handler

	def handle(self, message: access.AccessMessage) -> Optional[ModelMessage]:
		try:
			handler = self.handlers[message.opcode]
			response = handler(message)
			if response:
				return response
			else:
				return None
		except KeyError:
			raise UnknownOpcode(str(message.opcode))

	def send(self, msg: access.AccessMessage) -> None:
		raise NotImplementedError()

class StatusMessage(ModelMessage, ABC):
	pass

class SetMessage(ModelMessage, ABC):
	pass


class StatusStateServer(State, ABC):
	def __init__(self, status_opcode: access.Opcode) -> None:
		super().__init__()
		self.status_opcode = status_opcode

	def publish(self, status_message: StatusMessage) -> None:
		raise NotImplementedError()

	def publish_status(self) -> None:
		self.publish(self.status())

	def status(self) -> StatusMessage:
		raise NotImplementedError()



class GetStateServer(StatusStateServer, ABC):
	def __init__(self, status_opcode: access.Opcode, get_opcode: access.Opcode) -> None:
		super().__init__(status_opcode)
		self.get_opcode = get_opcode
		self.add_handler(get_opcode, self.on_get)

	def on_get(self, msg: access.AccessMessage) -> Optional[ModelMessage]:
		if msg.payload:
			return # we're expected an empty message
		return self.status()

	def get(self, get_request: ModelMessage) -> None:
		get_request.to_bytes()



class StatusStateClient(State):
	def __init__(self, status_opcode: access.Opcode):
		super().__init__()
		self.status_opcode = status_opcode
		self.add_handler(status_opcode, self.on_status)

	def on_status(self, msg: access.AccessMessage) -> None:
		raise NotImplementedError()

class GetStateClient(StatusStateClient):
	def __init__(self, get_opcode: access.Opcode, status_opcode: access.Opcode) -> None:
		super().__init__(status_opcode)
		self.get_opcode = get_opcode

	def get(self) -> None:



class SetStateServer(StatusStateServer, ABC):

	def __init__(self, status_opcode: access.Opcode, set_ack_opcode: Optional[access.Opcode], set_no_ack_opcode: Optional[access.Opcode]):
		if set_ack_opcode is None and set_no_ack_opcode is None:
			raise ValueError("no opcodes given")
		super().__init__(status_opcode)
		self.set_ack_opcode = set_ack_opcode
		self.set_no_ack_opcode = set_no_ack_opcode
		if set_ack_opcode:
			self.add_handler(set_ack_opcode, self.on_set_ack)
		if set_no_ack_opcode:
			self.add_handler(set_no_ack_opcode, self.on_set_no_ack)

	def set(self, msg: access.AccessMessage) -> Optional[StatusMessage]:
		raise NotImplementedError()

	def on_set_ack(self, msg: access.AccessMessage) -> Optional[StatusMessage]:
		return self.set(msg)

	def on_set_no_ack(self, msg: access.AccessMessage) -> None:
		response = self.set(msg)
		if response:
			self.publish(response)

class SetStateClient(GetStateClient, ABC):
	def __init__(self, status_opcode: access.Opcode, get_opcode: access.Opcode, set_ack_opcode: Optional[access.Opcode], set_no_ack_opcode: Optional[access.Opcode]) -> None:
		if set_ack_opcode is None and set_no_ack_opcode is None:
			raise ValueError("no opcodes given")
		super().__init__(status_opcode, get_opcode)
		self.set_ack_opcode = set_ack_opcode
		self.set_no_ack_opcode = set_no_ack_opcode




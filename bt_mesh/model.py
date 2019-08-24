from abc import ABC

from .mesh import *
from . import access
from .access import ModelID
from .foundation import PublishPeriod

class ModelMessage(ByteSerializable, ABC):
	pass


class EmptyModelMessage(ModelMessage):
	def __init__(self) -> None:
		pass

	def to_bytes(self) -> bytes:
		return bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'EmptyModelMessage':
		if len(b) != 0:
			raise ValueError("bytes must be empty")
		return cls()


HandlerCallable = Callable[Optional[ModelMessage], access.AccessMessage]


class MessageHandler:
	def opcodes(self) -> List[access.Opcode]:
		raise NotImplementedError()

	def get_handler(self, opcode: access.Opcode) -> HandlerCallable:
		raise NotImplementedError()


class Model:
	__slots__ = "company_id", "model_id", "handlers", "states"

	def __init__(self, model_id: ModelID, company_id: Optional[CompanyID] = SIGCompanyID) -> None:
		self.model_id = model_id
		self.company_id = company_id
		self.handlers: Dict[access.Opcode, HandlerCallable] = dict()
		self.states: List['State'] = list()

	def add_handler(self, opcode: access.Opcode, callback: HandlerCallable) -> None:
		if opcode in self.handlers.values():
			raise ValueError(f"{str(opcode)} is already handled")
		self.handlers[opcode] = callback

	def add_state(self, state: 'State') -> None:
		for opcode, handler in state.handlers.items():
			self.add_handler(opcode, handler)
		self.states.append(state)

	def publish(self, opcode: access.Opcode, msg: ModelMessage) -> None:
		raise NotImplementedError("this is my job")


class ModelServer(Model):
	pass


class ModelClient(Model):
	pass


class UnknownOpcode(Exception):
	pass


class State:
	__slots__ = "handlers", "parent"

	def __init__(self):
		self.handlers: Dict[access.Opcode, HandlerCallable]
		self.parent: Optional[Model] = None

	def add_handler(self, opcode: access.Opcode, handler: Callable) -> None:
		if opcode in self.handlers.values():
			raise ValueError(f"handlers already handling f{str(opcode)}")
		self.handlers[opcode] = handler

	def opcodes(self) -> List[access.Opcode]:
		return self.handlers.values()

	def get_handler(self, opcode: access.Opcode) -> HandlerCallable:
		try:
			return self.handlers[opcode]
		except KeyError:
			raise UnknownOpcode(str(opcode))

	def publish(self, opcode: access.Opcode, msg: ModelMessage) -> None:
		if not self.parent:
			raise RuntimeError("model must be bound to parent")
		self.parent.publish(opcode, msg)


class StatusMessage(ModelMessage, ABC):
	pass


class SetMessage(ModelMessage, ABC):
	pass


class StatusStateServer(State, ABC):
	def __init__(self, status_opcode: access.Opcode) -> None:
		super().__init__()
		self.status_opcode = status_opcode

	def publish_status(self) -> None:
		self.publish(self.status_opcode, self.status())

	def status(self) -> StatusMessage:
		raise NotImplementedError()


class GetStateServer(StatusStateServer, ABC):
	def __init__(self, status_opcode: access.Opcode, get_opcode: access.Opcode) -> None:
		super().__init__(status_opcode)
		self.get_opcode = get_opcode
		self.add_handler(get_opcode, self.on_get)

	def on_get(self, msg: access.AccessMessage) -> Optional[ModelMessage]:
		if msg.payload:
			return  # we're expected an empty message
		return self.status()


class StatusStateClient(State, ABC):
	def __init__(self, status_opcode: access.Opcode):
		super().__init__()
		self.status_opcode = status_opcode
		self.add_handler(status_opcode, self.on_status)

	def on_status(self, msg: access.AccessMessage) -> None:
		raise NotImplementedError()


class GetStateClient(StatusStateClient, ABC):
	def __init__(self, get_opcode: access.Opcode, status_opcode: access.Opcode) -> None:
		super().__init__(status_opcode)
		self.get_opcode = get_opcode

	def request_get(self, get_request: ModelMessage) -> None:
		self.publish(self.get_opcode, get_request)


class SetStateServer(StatusStateServer, ABC):

	def __init__(self, status_opcode: access.Opcode, set_ack_opcode: Optional[access.Opcode],
				 set_no_ack_opcode: Optional[access.Opcode]):
		if set_ack_opcode is None and set_no_ack_opcode is None:
			raise ValueError("no opcodes given")
		super().__init__(status_opcode)
		self.set_ack_opcode = set_ack_opcode
		self.set_no_ack_opcode = set_no_ack_opcode
		if set_ack_opcode:
			self.add_handler(set_ack_opcode, self.on_set_ack)
		if set_no_ack_opcode:
			self.add_handler(set_no_ack_opcode, self.on_set_no_ack)

	def on_set(self, msg: access.AccessMessage, acking: bool) -> Optional[StatusMessage]:
		raise NotImplementedError()

	def on_set_ack(self, msg: access.AccessMessage) -> Optional[StatusMessage]:
		return self.on_set(msg, True)

	def on_set_no_ack(self, msg: access.AccessMessage) -> None:
		response = self.on_set(msg, False)
		if response:
			self.publish(self.status_opcode, response)


class SetStateClient(GetStateClient, ABC):
	def __init__(self, status_opcode: access.Opcode, get_opcode: access.Opcode, set_ack_opcode: Optional[access.Opcode],
				 set_no_ack_opcode: Optional[access.Opcode]) -> None:
		if set_ack_opcode is None and set_no_ack_opcode is None:
			raise ValueError("no opcodes given")
		super().__init__(status_opcode, get_opcode)
		self.set_ack_opcode = set_ack_opcode
		self.set_no_ack_opcode = set_no_ack_opcode

	def set(self, value: Any, ack: Optional[bool] = True) -> None:
		raise NotImplementedError()

	def request_set_ack(self, request: ModelMessage) -> None:
		self.publish(self.set_ack_opcode, request)

	def request_set_no_ack(self, request: ModelMessage) -> None:
		self.publish(self.set_no_ack_opcode, request)


from abc import ABC

from ..mesh import *
from .. import access, foundation
from ..access import ModelID
from threading import Condition


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


HandlerCallable = Callable[[Optional[ModelMessage], ], access.AccessMessage]


class MessageHandler:
	def opcodes(self) -> List[access.Opcode]:
		raise NotImplementedError()

	def get_handler(self, opcode: access.Opcode) -> HandlerCallable:
		raise NotImplementedError()


class Model:
	__slots__ = "company_id", "model_id", "handlers", "states", "publication", "send_access"

	def __init__(self, model_id: ModelID, company_id: Optional[CompanyID] = SIGCompanyID) -> None:
		self.model_id = model_id
		self.company_id = company_id
		self.handlers: Dict[access.Opcode, HandlerCallable] = dict()
		self.states: List['State'] = list()
		self.publication: Optional[foundation.ModelPublication] = None
		self.send_access: Optional[Callable[[access.AccessMessage], None]] = None

	def add_handler(self, opcode: access.Opcode, callback: HandlerCallable) -> None:
		if opcode in self.handlers.values():
			raise ValueError(f"{str(opcode)} is already handled")
		self.handlers[opcode] = callback

	def add_state(self, state: 'State') -> None:
		for opcode, handler in state.handlers.items():
			self.add_handler(opcode, handler)
		self.states.append(state)

	def publish(self, opcode: access.Opcode, msg: ModelMessage) -> None:
		access.AccessMessage(self.publication.element_address, self.publication.publish_address,
							 self.publication.publish_ttl,
							 opcode, msg.to_bytes(), self.publication.app_key_index, self.publication.net_key_index)


class ModelServer(Model):
	pass


class ModelClient(Model):
	def target(self, address: UnicastAddress, *, dev_key: bool = False, app_key_index: AppKeyIndex = None,
			   net_key_index: NetKeyIndex = None):
		assert self.publication, "missing publication"
		if dev_key:
			assert not app_key_index
			assert not net_key_index
			self.publication.net_key_index = None
			self.publication.app_key_index = AppKeyIndex(0)
		else:
			assert app_key_index
			assert net_key_index
			self.publication.net_key_index = net_key_index
			self.publication.app_key_index = app_key_index
		self.publication.element_address = address


class UnknownOpcode(Exception):
	pass


class State:
	__slots__ = "handlers", "parent"

	def __init__(self):
		self.handlers: Dict[access.Opcode, HandlerCallable] = dict()
		self.parent: Optional[Model] = None

	def add_handler(self, opcode: access.Opcode, handler: Callable) -> None:
		if opcode in self.handlers.values():
			raise ValueError(f"handlers already handling f{str(opcode)}")
		self.handlers[opcode] = handler

	def opcodes(self) -> KeysView[access.Opcode]:
		return self.handlers.keys()

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
		self.status_condition = Condition()
		self.add_handler(status_opcode, self.on_status)

	def status_handler(self, msg: access.AccessMessage) -> None:
		self.on_status(msg)
		self.status_condition.notify_all()

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
	def set(self, value: Any, ack: Optional[bool] = True) -> None:
		raise NotImplementedError()

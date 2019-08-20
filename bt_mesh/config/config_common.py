from ..model import *
from ..access import Opcode

class ConfigOpcode(Opcode, Enum):
	APPKEY_ADD = Opcode(0x00)
	APPKEY_DELETE = Opcode(0x8000)
	APPKEY_GET = Opcode(0x8001)
	APPKEY_LIST = Opcode(0x8002)
	APPKEY_STATUS = Opcode(0x8003)
	APPKEY_UPDATE = Opcode(0x01)
	BEACON_GET = Opcode(0x8009)
	BEACON_SET = Opcode(0x800A)
	BEACON_STATUS = Opcode(0x800B)
	COMPOSITION_DATA_GET = Opcode(0x8008)
	COMPOSITION_DATA_STATUS = Opcode(0x02)
	MODEL_PUBLICATION_SET = Opcode(0x03)
	DEFAULT_TTL_GET = Opcode(0x800C)
	DEFAULT_TTL_SET = Opcode(0x800D)
	DEFAULT_TTL_STATUS = Opcode(0x800E)
	FRIEND_GET = Opcode(0x800F)
	FRIEND_SET = Opcode(0x8010)
	FRIEND_STATUS = Opcode(0x8011)
	GATT_PROXY_GET = Opcode(0x8012)
	GATT_PROXY_SET = Opcode(0x8013)
	GATT_PROXY_STATUS = Opcode(0x8014)
	HEARTBEAT_PUBLICATION_GET = Opcode(0x8038)
	HEARTBEAT_PUBLICATION_SET = Opcode(0x8039)
	HEARTBEAT_PUBLICATION_STATUS = Opcode(0x06)
	HEARTBEAT_SUBSCRIPTION_GET = Opcode(0x803A)
	HEARTBEAT_SUBSCRIPTION_SET = Opcode(0x803B)
	HEARTBEAT_SUBSCRIPTION_STATUS = Opcode(0x803C)
	KEY_REFRESH_PHASE_GET = Opcode(0x8015)
	KEY_REFRESH_PHASE_SET = Opcode(0x8015)
	KEY_REFRESH_PHASE_STATUS = Opcode(0x8017)
	LOW_POWER_NODE_POLLTIMEOUT_GET = Opcode(0x802D)
	LOW_POWER_NODE_POLLTIMEOUT_STATUS = Opcode(0x802E)
	MODEL_APP_BIND = Opcode(0x803D)
	MODEL_APP_STATUS = Opcode(0x803E)
	MODEL_APP_UNBIND = Opcode(0x803F)
	MODEL_PUBLICATION_GET = Opcode(0x8018)
	MODEL_PUBLICATION_STATUS = Opcode(0x8019)
	MODEL_PUBLICATION_VIRTUAL_ADDRESS_SET = Opcode(0x801A)
	MODEL_SUBSCRIPTION_ADD = Opcode(0x801B)
	MODEL_SUBSCRIPTION_DELETE = Opcode(0x801C)
	MODEL_SUBSCRIPTION_DELETE_ALL = Opcode(0x801D)
	MODEL_SUBSCRIPTION_OVERWRITE = Opcode(0x801E)
	MODEL_SUBSCRIPTION_STATUS = Opcode(0x801F)
	MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_ADD = Opcode(0x8020)
	MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_DELETE = Opcode(0x8021)
	MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_OVERWRITE = Opcode(0x8022)
	NETKEY_ADD = Opcode(0x8040)
	NETKEY_DELETE = Opcode(0x8041)
	NETKEY_GET = Opcode(0x8042)
	NETKEY_LIST = Opcode(0x8043)
	NETKEY_STATUS = Opcode(0x8044)
	NETKEY_UPDATE = Opcode(0x8045)
	NETWORK_TRANSMIT_GET = Opcode(0x8023)
	NETWORK_TRANSMIT_SET = Opcode(0x8024)
	NETWORK_TRANSMIT_STATUS = Opcode(0x8025)
	NODE_IDENTITY_GET = Opcode(0x8046)
	NODE_IDENTITY_SET = Opcode(0x8047)
	NODE_IDENTITY_STATUS = Opcode(0x8048)
	NODE_RESET = Opcode(0x8049)
	NODE_RESET_STATUS = Opcode(0x804A)
	RELAY_GET = Opcode(0x8026)
	RELAY_SET = Opcode(0x8027)
	RELAY_STATUS = Opcode(0x8028)
	SIG_MODEL_APP_GET = Opcode(0x804B)
	SIG_MODEL_APP_LIST = Opcode(0x804C)
	SIG_MODEL_SUBSCRIPTION_GET = Opcode(0x8029)
	SIG_MODEL_SUBSCRIPTION_LIST = Opcode(0x802A)
	VENDOR_MODEL_APP_GET = Opcode(0x804D)
	VENDOR_MODEL_APP_LIST = Opcode(0x804E)
	VENDOR_MODEL_SUBSCRIPTION_GET = Opcode(0x802B)
	VENDOR_MODEL_SUBSCRIPTION_LIST = Opcode(0x802C)

class SecureBeaconState(U8, Enum):
	NotBroadcast = U8(0x00)
	IsBroadcasting = U8(0x01)

class GATTProxyState(U8, Enum):
	Disabled = U8(0x00)
	Enabled = U8(0x01)
	NotSupported = U8(0x02)

class RelayState(U8, Enum):
	Disabled = U8(0x00)
	Enabled = U8(0x01)
	NotSupported = U8(0x02)


class NodeIdentityState(U8, Enum):
	Stopped = U8(0x00)
	Running = U8(0x01)
	NotSupported = U8(0x02)

class FriendState(U8, Enum):
	Disabled = U8(0x00)
	Enabled = U8(0x01)
	NotSupported = U8(0x02)

class KeyRefreshState(U8, Enum):
	Normal = U8(0x00)
	FirstPhase = U8(0x01)
	SecondPhase = U8(0x02)

class CurrentFaultState:
	__slots__ = "test_id", "fault_array"

class Beacon:
	class Get(EmptyModelMessage):
		pass

	class Set(ModelMessage):
		__slots__ = "beacon_state",

		def __init__(self, beacon_state: SecureBeaconState) -> None:
			self.beacon_state = beacon_state

		def to_bytes(self) -> bytes:
			return self.beacon_state.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Beacon.Set':
			return cls(SecureBeaconState.from_bytes(b))

	class Status(StatusMessage):
		__slots__ = "beacon_state",

		def __init__(self, beacon_state: U8) -> None:
			self.beacon_state = beacon_state

		def to_bytes(self) -> bytes:
			return self.beacon_state.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Beacon.Status':
			return cls(U8.from_bytes(b))


class CompositionData:
	class Get(ModelMessage):
		__slots__ = "page_number",

		def __init__(self, page_number: U8) -> None:
			self.page_number = page_number

		def to_bytes(self) -> bytes:
			return self.page_number.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'CompositionData.Get':
			return cls(U8.from_bytes(b))

	class Status(StatusMessage):
		__slots__ = "page_number", "data"

		def __init__(self, page_number: U8, data: bytes) -> None:
			self.page_number = page_number
			self.data = data

		def to_bytes(self) -> bytes:
			return self.page_number.to_bytes() + self.data

		@classmethod
		def from_bytes(cls, b: bytes) -> 'CompositionData.Status':
			return cls(U8(b[0]), b[1:])


class DefaultTTL:
	class Get(EmptyModelMessage):
		pass

	class Set(ModelMessage):
		__slots__ = "ttl",

		def __init__(self, ttl: TTL):
			self.ttl = ttl

		def to_bytes(self) -> bytes:
			return self.ttl.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'DefaultTTL.Set':
			return cls(TTL.from_bytes(b))

	class Status(StatusMessage):
		__slots__ = "ttl",

		def __init__(self, ttl: TTL):
			self.ttl = ttl

		def to_bytes(self) -> bytes:
			return self.ttl.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'DefaultTTL.Status':
			return cls(TTL.from_bytes(b))


class GATTProxy:
	class Get(EmptyModelMessage):
		pass

	class Set(ModelMessage):
		__slots__ = "gatt_proxy_state",

		def __init__(self, gatt_proxy_state: U8) -> None:
			self.beacon_state = gatt_proxy_state

		def to_bytes(self) -> bytes:
			return self.gatt_proxy_state.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'GATTProxy.Set':
			return cls(U8.from_bytes(b))

	class Status(StatusMessage):
		__slots__ = "gatt_proxy_state",

		def __init__(self, gatt_proxy_state: U8) -> None:
			self.beacon_state = gatt_proxy_state

		def to_bytes(self) -> bytes:
			return self.beacon_state.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'GATTProxy.Status':
			return cls(U8.from_bytes(b))


class Relay:
	class Get(EmptyModelMessage):
		pass

	class Set(ModelMessage):
		__slots__ = "relay_state", "retransmit_parameters"

		def __init__(self, relay_state: relay.State, retransmit_parameters: RetransmitParameters) -> None:
			self.relay_state = relay_state
			self.retransmit_parameters = retransmit_parameters

		def to_bytes(self) -> bytes:
			return self.relay_state.to_bytes() + self.retransmit_parameters.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Relay.Set':
			return cls(relay.State.from_bytes(b[:1]), RetransmitParameters.from_bytes(b[1:]))

	class Status(StatusMessage):
		__slots__ = "relay_state", "retransmit_parameters"

		def __init__(self, relay_state: relay.State, retransmit_parameters: RetransmitParameters) -> None:
			self.relay_state = relay_state
			self.retransmit_parameters = retransmit_parameters

		def to_bytes(self) -> bytes:
			return self.relay_state.to_bytes() + self.retransmit_parameters.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Relay.Status':
			return cls(relay.State.from_bytes(b[:1]), RetransmitParameters.from_bytes(b[1:]))


class ASD:
	class Get(EmptyModelMessage):
		pass

	class Set(ModelMessage):
		__slots__ = "beacon_state",

		def __init__(self, beacon_state: U8) -> None:
			self.beacon_state = beacon_state

		def to_bytes(self) -> bytes:
			return self.beacon_state.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Beacon.Set':
			return cls(U8.from_bytes(b))

	class Status(StatusMessage):
		__slots__ = "beacon_state",

		def __init__(self, beacon_state: U8) -> None:
			self.beacon_state = beacon_state

		def to_bytes(self) -> bytes:
			return self.beacon_state.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Beacon.Status':
			return cls(U8.from_bytes(b))


class ASD:
	class Get(EmptyModelMessage):
		pass

	class Set(ModelMessage):
		__slots__ = "beacon_state",

		def __init__(self, beacon_state: U8) -> None:
			self.beacon_state = beacon_state

		def to_bytes(self) -> bytes:
			return self.beacon_state.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Beacon.Set':
			return cls(U8.from_bytes(b))

	class Status(StatusMessage):
		__slots__ = "beacon_state",

		def __init__(self, beacon_state: SecureBeaconState) -> None:
			self.beacon_state = beacon_state

		def to_bytes(self) -> bytes:
			return self.beacon_state.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Beacon.Status':
			return cls(U8.from_bytes(b))

from ..model import *
from ..access import Opcode
from .. import foundation
config_server_id = ModelID(0x0000)
config_client_id = ModelID(0x0001)


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


class NetKeyStatus(foundation.Status):
	pass

class AppKeyStatus(foundation.Status):
	pass

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

		def __init__(self, relay_state: RelayState, retransmit_parameters: RetransmitParameters) -> None:
			self.relay_state = relay_state
			self.retransmit_parameters = retransmit_parameters

		def to_bytes(self) -> bytes:
			return self.relay_state.to_bytes() + self.retransmit_parameters.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Relay.Set':
			return cls(RelayState.from_bytes(b[:1]), RetransmitParameters.from_bytes(b[1:]))

	class Status(StatusMessage):
		__slots__ = "relay_state", "retransmit_parameters"

		def __init__(self, relay_state: RelayState, retransmit_parameters: RetransmitParameters) -> None:
			self.relay_state = relay_state
			self.retransmit_parameters = retransmit_parameters

		def to_bytes(self) -> bytes:
			return self.relay_state.to_bytes() + self.retransmit_parameters.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Relay.Status':
			return cls(RelayState.from_bytes(b[:1]), RetransmitParameters.from_bytes(b[1:]))


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



class NetKeyList:
	class NetKeyIndexMessage(ModelMessage):
		__slots__ = "key_index", "key"

		def __init__(self, key_index: KeyIndex, key: crypto.NetworkKey) -> None:
			self.key_index = key_index
			self.key = key

		def to_bytes(self) -> bytes:
			return self.key_index.to_bytes() + self.key.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'NetKeyList.NetKeyIndexMessage':
			return cls(NetKeyIndex.from_bytes(b[:2]), crypto.NetworkKey.from_bytes(b[2:]))

	class Add(NetKeyIndexMessage):
		pass

	class Update(NetKeyIndexMessage):
		pass

	class Delete(ModelMessage):
		__slots__ = "net_key_index"

		def __init__(self, net_key_index: NetKeyIndex) -> None:
			self.net_key_index = net_key_index

		def to_bytes(self) -> bytes:
			return self.net_key_index.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'NetKeyList.Delete':
			return cls(NetKeyIndex.from_bytes(b))

	class Status(StatusMessage):
		__slots__ = "status", "net_key_index"

		def __init__(self, status: NetKeyStatus, net_key_index: NetKeyIndex) -> None:
			self.status = status
			self.net_key_index = net_key_index

		def to_bytes(self) -> bytes:
			return self.status.to_bytes() + self.net_key_index.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'NetKeyList.Status':
			return cls(NetKeyStatus.from_bytes(b[:1]), NetKeyIndex.from_bytes(b[1:]))

	class Get(EmptyModelMessage):
		pass

	class List(ModelMessage):
		__slots__ = "status", "net_key_indexes",

		def __init__(self, status: NetKeyStatus, net_key_indexes: List[NetKeyIndex]) -> None:
			self.net_key_indexes = net_key_indexes
			self.status = status

		def to_bytes(self) -> bytes:
			return self.status.to_bytes() + bytes().join([index.to_bytes() for index in self.net_key_indexes])

		@classmethod
		def from_bytes(cls, b: bytes) -> 'NetKeyList.List':
			indexes: List[NetKeyIndex] = list()
			status = NetKeyStatus.from_bytes(b[:1])
			i_b = b[1:]
			for i in range(0, len(i_b) // 3, 3):
				i_0, i_1 = NetKeyIndex.unjoin(i_b[i:i + 3])
				indexes.append(i_0)
				indexes.append(i_1)

			if len(i_b) % 3 != 0:
				indexes.append(NetKeyIndex.from_bytes(i_b[-2:]))
			return cls(status, indexes)


class AppKeyList:
	class AppKeyIndexMessage(ModelMessage):
		__slots__ = "net_key_index", "app_key_index", "key"

		def __init__(self, net_key_index: NetKeyIndex, app_key_index: AppKeyIndex, key: crypto.NetworkKey) -> None:
			self.net_key_index = net_key_index
			self.app_key_index = app_key_index
			self.key = key

		def to_bytes(self) -> bytes:
			return self.net_key_index.join(self.app_key_index) + self.key.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'AppKeyList.AppKeyIndexMessage':
			net_key_index, app_key_index = cast(Tuple[NetKeyIndex, AppKeyIndex], KeyIndex.unjoin(b[:2]))
			return cls(net_key_index, app_key_index, crypto.NetworkKey.from_bytes(b[2:]))

	class Add(AppKeyIndexMessage):
		pass

	class Update(AppKeyIndexMessage):
		pass

	class Delete(ModelMessage):
		__slots__ = "net_key_index", "app_key_index"

		def __init__(self, net_key_index: NetKeyIndex, app_key_index: AppKeyIndex) -> None:
			self.net_key_index = net_key_index
			self.app_key_index = app_key_index

		def to_bytes(self) -> bytes:
			return self.net_key_index.join(self.app_key_index)

		@classmethod
		def from_bytes(cls, b: bytes) -> 'AppKeyList.Delete':
			return cls(*cast(Tuple[NetKeyIndex, AppKeyIndex], KeyIndex.unjoin(b)))

	class Status(ModelMessage):
		__slots__ = "status", "net_key_index", "app_key_index"

		def __init__(self, status: AppKeyStatus, net_key_index: NetKeyIndex, app_key_index: NetKeyIndex) -> None:
			self.status = status
			self.net_key_index = net_key_index
			self.app_key_index = app_key_index

		def to_bytes(self) -> bytes:
			return self.status.to_bytes() + self.net_key_index.join(self.app_key_index)

		@classmethod
		def from_bytes(cls, b: bytes) -> 'AppKeyList.Status':
			return cls(AppKeyStatus.from_bytes(b[:1]), *cast(Tuple[NetKeyIndex, AppKeyIndex], KeyIndex.unjoin(b[1:])))

	class Get(ModelMessage):
		__slots__ = "net_key_index",
		def __init__(self, net_key_index: NetKeyIndex) -> None:
			self.net_key_index = net_key_index

		def to_bytes(self) -> bytes:
			self.net_key_index.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'AppKeyList.Get':
			return cls(NetKeyIndex.from_bytes(b))

	class List(ModelMessage):
		__slots__ = "net_key_index", "app_key_indexes", "status"

		def __init__(self, status: AppKeyStatus, net_key_index: NetKeyIndex, app_key_indexes: List[AppKeyIndex]) -> None:
			self.status = status
			self.net_key_index = net_key_index
			self.app_key_indexes = app_key_indexes

		def to_bytes(self) -> bytes:
			return self.status.to_bytes() + self.net_key_index.to_bytes() + \
				   bytes().join([index.to_bytes() for index in self.app_key_indexes])

		@classmethod
		def from_bytes(cls, b: bytes) -> 'AppKeyList.List':
			indexes: List[AppKeyIndex] = list()
			status = AppKeyStatus.from_bytes(b[:1])
			net_key_index = NetKeyIndex.from_bytes(b[1:3])
			i_b = b[3:]
			for i in range(0, len(i_b) // 3, 3):
				i_0, i_1 = AppKeyIndex.unjoin(i_b[i:i+3])
				indexes.append(i_0)
				indexes.append(i_1)

			if len(i_b) % 3 != 0:
				indexes.append(AppKeyIndex.from_bytes(i_b[-2:]))
			return cls(status, net_key_index, indexes)

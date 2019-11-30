from ..models.model import *
from ..access import Opcode
from .. import foundation, crypto

config_server_id = ModelID(0x0000)
config_client_id = ModelID(0x0001)


class ConfigOpcode(Opcode, Enum):
	APPKEY_ADD = 0x00
	APPKEY_DELETE = 0x8000
	APPKEY_GET = 0x8001
	APPKEY_LIST = 0x8002
	APPKEY_STATUS = 0x8003
	APPKEY_UPDATE = 0x01
	BEACON_GET = 0x8009
	BEACON_SET = 0x800A
	BEACON_STATUS = 0x800B
	COMPOSITION_DATA_GET = 0x8008
	COMPOSITION_DATA_STATUS = 0x02
	MODEL_PUBLICATION_SET = 0x03
	DEFAULT_TTL_GET = 0x800C
	DEFAULT_TTL_SET = 0x800D
	DEFAULT_TTL_STATUS = 0x800E
	FRIEND_GET = 0x800F
	FRIEND_SET = 0x8010
	FRIEND_STATUS = 0x8011
	GATT_PROXY_GET = 0x8012
	GATT_PROXY_SET = 0x8013
	GATT_PROXY_STATUS = 0x8014
	HEARTBEAT_PUBLICATION_GET = 0x8038
	HEARTBEAT_PUBLICATION_SET = 0x8039
	HEARTBEAT_PUBLICATION_STATUS = 0x06
	HEARTBEAT_SUBSCRIPTION_GET = 0x803A
	HEARTBEAT_SUBSCRIPTION_SET = 0x803B
	HEARTBEAT_SUBSCRIPTION_STATUS = 0x803C
	KEY_REFRESH_PHASE_GET = 0x8015
	KEY_REFRESH_PHASE_SET = 0x8015
	KEY_REFRESH_PHASE_STATUS = 0x8017
	LOW_POWER_NODE_POLLTIMEOUT_GET = 0x802D
	LOW_POWER_NODE_POLLTIMEOUT_STATUS = 0x802E
	MODEL_APP_BIND = 0x803D
	MODEL_APP_STATUS = 0x803E
	MODEL_APP_UNBIND = 0x803F
	MODEL_PUBLICATION_GET = 0x8018
	MODEL_PUBLICATION_STATUS = 0x8019
	MODEL_PUBLICATION_VIRTUAL_ADDRESS_SET = 0x801A
	MODEL_SUBSCRIPTION_ADD = 0x801B
	MODEL_SUBSCRIPTION_DELETE = 0x801C
	MODEL_SUBSCRIPTION_DELETE_ALL = 0x801D
	MODEL_SUBSCRIPTION_OVERWRITE = 0x801E
	MODEL_SUBSCRIPTION_STATUS = 0x801F
	MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_ADD = 0x8020
	MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_DELETE = 0x8021
	MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_OVERWRITE = 0x8022
	NETKEY_ADD = 0x8040
	NETKEY_DELETE = 0x8041
	NETKEY_GET = 0x8042
	NETKEY_LIST = 0x8043
	NETKEY_STATUS = 0x8044
	NETKEY_UPDATE = 0x8045
	NETWORK_TRANSMIT_GET = 0x8023
	NETWORK_TRANSMIT_SET = 0x8024
	NETWORK_TRANSMIT_STATUS = 0x8025
	NODE_IDENTITY_GET = 0x8046
	NODE_IDENTITY_SET = 0x8047
	NODE_IDENTITY_STATUS = 0x8048
	NODE_RESET = 0x8049
	NODE_RESET_STATUS = 0x804A
	RELAY_GET = 0x8026
	RELAY_SET = 0x8027
	RELAY_STATUS = 0x8028
	SIG_MODEL_APP_GET = 0x804B
	SIG_MODEL_APP_LIST = 0x804C
	SIG_MODEL_SUBSCRIPTION_GET = 0x8029
	SIG_MODEL_SUBSCRIPTION_LIST = 0x802A
	VENDOR_MODEL_APP_GET = 0x804D
	VENDOR_MODEL_APP_LIST = 0x804E
	VENDOR_MODEL_SUBSCRIPTION_GET = 0x802B
	VENDOR_MODEL_SUBSCRIPTION_LIST = 0x802C


class SecureBeaconState(U8, Enum):
	NotBroadcast = 0x00
	IsBroadcasting = 0x01


class GATTProxyState(U8, Enum):
	Disabled = 0x00
	Enabled = 0x01
	NotSupported = 0x02


class RelayState(U8, Enum):
	Disabled = 0x00
	Enabled = 0x01
	NotSupported = 0x02


class NodeIdentityState(U8, Enum):
	Stopped = 0x00
	Running = 0x01
	NotSupported = 0x02


class FriendState(U8, Enum):
	Disabled = 0x00
	Enabled = 0x01
	NotSupported = 0x02


class KeyRefreshState(U8, Enum):
	Normal = 0x00
	FirstPhase = 0x01
	SecondPhase = 0x02


NetKeyStatus = foundation.Status


AppKeyStatus = foundation.Status



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

		def __init__(self, page_number: U8, data: foundation.CompositionDataPage) -> None:
			self.page_number = page_number
			self.data = data

		def to_bytes(self) -> bytes:
			return self.page_number.to_bytes() + self.data

		@classmethod
		def from_bytes(cls, b: bytes) -> 'CompositionData.Status':
			page_num = U8(b[0])
			if page_num != 0:
				raise ValueError(f"unknown page number: {page_num}")
			return cls(page_num, foundation.CompositionDataPage0.from_bytes(b[1:]))


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

		def __init__(self, relay_state: RelayState, retransmit_parameters: RelayRetransmitParameters) -> None:
			self.relay_state = relay_state
			self.retransmit_parameters = retransmit_parameters

		def to_bytes(self) -> bytes:
			return self.relay_state.to_bytes() + self.retransmit_parameters.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Relay.Set':
			return cls(RelayState.from_bytes(b[:1]), RelayRetransmitParameters.from_bytes(b[1:]))

	class Status(StatusMessage):
		__slots__ = "relay_state", "retransmit_parameters"

		def __init__(self, relay_state: RelayState, retransmit_parameters: RelayRetransmitParameters) -> None:
			self.relay_state = relay_state
			self.retransmit_parameters = retransmit_parameters

		def to_bytes(self) -> bytes:
			return self.relay_state.to_bytes() + self.retransmit_parameters.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'Relay.Status':
			return cls(RelayState.from_bytes(b[:1]), RelayRetransmitParameters.from_bytes(b[1:]))


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
			return self.net_key_index.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'AppKeyList.Get':
			return cls(NetKeyIndex.from_bytes(b))

	class List(ModelMessage):
		__slots__ = "net_key_index", "app_key_indexes", "status"

		def __init__(self, status: AppKeyStatus, net_key_index: NetKeyIndex,
					 app_key_indexes: List[AppKeyIndex]) -> None:
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
				i_0, i_1 = AppKeyIndex.unjoin(i_b[i:i + 3])
				indexes.append(i_0)
				indexes.append(i_1)

			if len(i_b) % 3 != 0:
				indexes.append(AppKeyIndex.from_bytes(i_b[-2:]))
			return cls(status, net_key_index, indexes)


class ModelPublication:
	class Get(ModelMessage):
		__slots__ = "element_address", "model_identifier"

		def __init__(self, element_address: UnicastAddress, model_identifier: access.ModelIdentifier) -> None:
			self.element_address = element_address
			self.model_identifier = model_identifier

		def to_bytes(self) -> bytes:
			return self.element_address.to_bytes() + self.model_identifier.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'ModelPublication.Get':
			return cls(UnicastAddress.from_bytes(b[:2]), access.ModelIdentifier.from_bytes(b[2:]))

	class Set(ModelMessage):
		__slots__ = "model_publication",

		def __init__(self, model_publication: foundation.ModelPublication) -> None:
			self.model_publication = model_publication

		def to_bytes(self) -> bytes:
			return self.model_publication.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'ModelPublication.Set':
			return cls(foundation.ModelPublication.from_bytes(b))

	class Status(StatusMessage):
		__slots__ = "status", "model_publication",

		def __init__(self, status: foundation.Status, model_publication: foundation.ModelPublication) -> None:
			self.status = status
			self.model_publication = model_publication

		def to_bytes(self) -> bytes:
			return self.status.to_bytes() + self.model_publication.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'ModelPublication.Status':
			return cls(foundation.Status.from_bytes(b[:1]), access.ModelIdentifier.from_bytes(b[1:]))


class ModelSubscription:
	class Add(ModelMessage):
		__slots__ = "element_address", "address", "model_identifier"

		def __init__(self, element_address: UnicastAddress, address: Union[GroupAddress, VirtualAddress],
					 model_identifier: access.ModelIdentifier) -> None:
			self.element_address = element_address
			self.address = address
			self.model_identifier = model_identifier

		def to_bytes(self) -> bytes:
			if isinstance(self.address, VirtualAddress):
				return self.element_address.to_bytes() + self.address.uuid.bytes + self.model_identifier.to_bytes()
			else:
				return self.element_address.to_bytes() + self.address.to_bytes() + self.model_identifier.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'ModelSubscription.Add':
			if len(b) > (2 + 2 + 4):
				element_address = UnicastAddress.from_bytes(b[:2])
				label = VirtualAddress(UUID(bytes=b[2:18]))
				model_identifier = access.ModelIdentifier.from_bytes(b[18:])
				return cls(element_address, label, model_identifier)
			else:
				element_address = UnicastAddress.from_bytes(b[:2])
				address = GroupAddress.from_bytes(b[2:4])
				model_identifier = access.ModelIdentifier.from_bytes(b[4:])
				return cls(element_address, address, model_identifier)

	class Delete(ModelMessage):
		__slots__ = "element_address", "address", "model_identifier"

		def __init__(self, element_address: UnicastAddress, address: Union[GroupAddress, VirtualAddress],
					 model_identifier: access.ModelIdentifier) -> None:
			self.element_address = element_address
			self.address = address
			self.model_identifier = model_identifier

		def to_bytes(self) -> bytes:
			if isinstance(self.address, VirtualAddress):
				return self.element_address.to_bytes() + self.address.uuid.bytes + self.model_identifier.to_bytes()
			else:
				return self.element_address.to_bytes() + self.address.to_bytes() + self.model_identifier.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'ModelSubscription.Delete':
			if len(b) > (2 + 2 + 4):
				element_address = UnicastAddress.from_bytes(b[:2])
				label = VirtualAddress(UUID(bytes=b[2:18]))
				model_identifier = access.ModelIdentifier.from_bytes(b[18:])
				return cls(element_address, label, model_identifier)
			else:
				element_address = UnicastAddress.from_bytes(b[:2])
				address = GroupAddress.from_bytes(b[2:4])
				model_identifier = access.ModelIdentifier.from_bytes(b[4:])
				return cls(element_address, address, model_identifier)

	class Overwrite(ModelMessage):
		__slots__ = "element_address", "address", "model_identifier"

		def __init__(self, element_address: UnicastAddress, address: Union[GroupAddress, VirtualAddress],
					 model_identifier: access.ModelIdentifier) -> None:
			self.element_address = element_address
			self.address = address
			self.model_identifier = model_identifier

		def to_bytes(self) -> bytes:
			if isinstance(self.address, VirtualAddress):
				return self.element_address.to_bytes() + self.address.uuid.bytes + self.model_identifier.to_bytes()
			else:
				return self.element_address.to_bytes() + self.address.to_bytes() + self.model_identifier.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'ModelSubscription.Overwrite':
			if len(b) > (2 + 2 + 4):
				element_address = UnicastAddress.from_bytes(b[:2])
				label = VirtualAddress(UUID(bytes=b[2:18]))
				model_identifier = access.ModelIdentifier.from_bytes(b[18:])
				return cls(element_address, label, model_identifier)
			else:
				element_address = UnicastAddress.from_bytes(b[:2])
				address = GroupAddress.from_bytes(b[2:4])
				model_identifier = access.ModelIdentifier.from_bytes(b[4:])
				return cls(element_address, address, model_identifier)

	class DeleteAll(ModelMessage):
		__slots__ = "element_address", "model_identifier"

		def __init__(self, element_address: UnicastAddress, model_identifier: access.ModelIdentifier) -> None:
			self.element_address = element_address
			self.model_identifier = model_identifier

		def to_bytes(self) -> bytes:
			return self.element_address.to_bytes() + self.model_identifier.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'ModelSubscription.DeleteAll':
			element_address = UnicastAddress.from_bytes(b[:2])
			model_identifier = access.ModelIdentifier.from_bytes(b[2:])
			return cls(element_address, model_identifier)

	class Get(ModelMessage):
		__slots__ = "element_address", "model_identifier"

		def __init__(self, element_address: UnicastAddress, model_identifier: access.ModelIdentifier) -> None:
			self.element_address = element_address
			self.model_identifier = model_identifier

		def to_bytes(self) -> bytes:
			return self.element_address.to_bytes() + self.model_identifier.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'ModelSubscription.Get':
			element_address = UnicastAddress.from_bytes(b[:2])
			model_identifier = access.ModelIdentifier.from_bytes(b[2:])
			return cls(element_address, model_identifier)

	class Status(StatusMessage):
		__slots__ = "status", "element_address", "address", "model_identifier"

		def __init__(self, status: foundation.Status, element_address: UnicastAddress, address: Address,
					 model_identifier: access.ModelIdentifier) -> None:
			self.status = status
			self.element_address = element_address
			self.address = address
			self.model_identifier = model_identifier

		def to_bytes(self) -> bytes:
			return self.status.to_bytes() + self.element_address.to_bytes() + self.address.to_bytes() + self.model_identifier.to_bytes()

		@classmethod
		def from_bytes(cls, b: bytes) -> 'ModelSubscription.Status':
			return cls(foundation.Status.from_bytes(b[:1]), UnicastAddress.from_bytes(b[1:3]),
					   Address.from_bytes(b[3:5]),
					   access.ModelIdentifier.from_bytes(b[5:]))

	class List(ModelMessage, ABC):
		__slots__ = "status", "element_address", "model_identifier", "addresses"

		def __init__(self, status: foundation.Status, element_address: UnicastAddress,
					 model_identifier: access.ModelIdentifier, addresses: List[Address]) -> None:
			self.status = status
			self.element_address = element_address
			self.model_identifier = model_identifier

	class SIGList(List):
		def to_bytes(self) -> bytes:
			if self.model_identifier.company_id != SIGCompanyID:
				raise ValueError("expected sig company id")
			return self.status.to_bytes() + self.element_address.to_bytes() + self.model_identifier.to_bytes() + \
				   bytes().join([address.to_bytes() for address in self.addresses])

		@classmethod
		def from_bytes(cls, b: bytes) -> 'ModelSubscription.SIGList':
			status = foundation.Status.from_bytes(b[:1])
			element_address = UnicastAddress.from_bytes(b[1:3])
			model_identifier = access.ModelIdentifier.from_bytes(b[3:5])
			addresses: List[Address] = list()
			for i in range(5, len(b), 2):
				addresses.append(Address.from_bytes(b[i:i+2]))
			return cls(status, element_address, model_identifier, addresses)

	class VendorList(List):
		def to_bytes(self) -> bytes:
			if self.model_identifier.company_id == SIGCompanyID:
				raise ValueError("expected vendor company id")
			return self.status.to_bytes() + self.element_address.to_bytes() + self.model_identifier.to_bytes() + \
				   bytes().join([address.to_bytes() for address in self.addresses])

		@classmethod
		def from_bytes(cls, b: bytes) -> 'ModelSubscription.VendorList':
			status = foundation.Status.from_bytes(b[:1])
			element_address = UnicastAddress.from_bytes(b[1:3])
			model_identifier = access.ModelIdentifier.from_bytes(b[3:7])
			addresses: List[Address] = list()
			for i in range(7, len(b), 2):
				addresses.append(Address.from_bytes(b[i:i+2]))
			return cls(status, element_address, model_identifier, addresses)

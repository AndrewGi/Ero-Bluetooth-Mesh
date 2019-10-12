from ..models import model
from .config_common import *


class SecureNetworkBeaconStateClient(SetStateClient):
	def __init__(self, initial_state: Optional[SecureBeaconState] = None) -> None:
		super().__init__(ConfigOpcode.BEACON_STATUS, ConfigOpcode.BEACON_GET)
		self.state = initial_state

	def get(self) -> None:
		self.request_get(Beacon.Get())

	def set(self, new_state: SecureBeaconState, ack: Optional[bool] = True) -> None:
		assert ack
		self.publish(ConfigOpcode.BEACON_SET, Beacon.Set(new_state))

	def on_status(self, msg: access.AccessMessage) -> None:
		self.state = Beacon.Status.from_bytes(msg.payload)


class RelayStateClient(SetStateClient):
	FullState = Tuple[RelayState, RelayRetransmitParameters]

	def __init__(self, initial_state: Optional[FullState] = None):
		super().__init__(ConfigOpcode.RELAY_STATUS, ConfigOpcode.RELAY_GET)
		self.state = initial_state

	def get(self) -> None:
		self.request_get(Relay.Get())

	def set(self, new_state: FullState, ack: Optional[bool] = True) -> None:
		assert ack
		self.publish(ConfigOpcode.RELAY_SET, Relay.Set(self.relay_state(), self.retransmit_parameters()))

	def relay_state(self) -> RelayState:
		return self.state[0]

	def retransmit_parameters(self) -> RelayRetransmitParameters:
		return self.state[1]

	def on_status(self, msg: access.AccessMessage) -> None:
		self.state = Relay.Status.from_bytes(msg.payload)


class NetKeyListStateClient(State):
	def __init__(self) -> None:
		super().__init__()
		self.key_index_list: List[NetKeyIndex] = list()
		self.last_status: foundation.Status = NetKeyStatus.Success
		self.add_handler(ConfigOpcode.NETKEY_LIST, self.on_list)
		self.add_handler(ConfigOpcode.NETKEY_STATUS, self.on_status)

	def add(self, new_key: crypto.NetworkKey, index: NetKeyIndex) -> None:
		self.publish(ConfigOpcode.NETKEY_ADD, NetKeyList.Add(index, new_key))

	def update(self, new_key: crypto.NetworkKey, index: NetKeyIndex) -> None:
		self.publish(ConfigOpcode.NETKEY_UPDATE, NetKeyList.Update(index, new_key))

	def delete(self, index: NetKeyIndex) -> None:
		self.publish(ConfigOpcode.NETKEY_DELETE, NetKeyList.Delete(index))

	def get(self) -> None:
		self.publish(ConfigOpcode.NETKEY_GET, NetKeyList.Get())

	def check_status(self) -> None:
		if self.last_status != NetKeyStatus.Success:
			raise ValueError(f"bad status {self.last_status}")

	def on_list(self, msg: access.AccessMessage) -> None:
		new_list = NetKeyList.List.from_bytes(msg.payload)
		self.last_status = new_list.status
		self.check_status()
		self.key_index_list = new_list.net_key_indexes

	def on_status(self, msg: access.AccessMessage):
		new_status = NetKeyList.Status.from_bytes(msg.payload)
		self.last_status = new_status.status
		self.check_status()


class AppKeyListStateClient(State):
	def __init__(self) -> None:
		super().__init__()
		self.key_index_list: Dict[NetKeyIndex, List[AppKeyIndex]] = dict()
		self.last_status: foundation.Status = AppKeyStatus.Success
		self.add_handler(ConfigOpcode.APPKEY_LIST, self.on_list)
		self.add_handler(ConfigOpcode.APPKEY_STATUS, self.on_status)

	def add(self, new_key: crypto.AppKey, app_index: AppKeyIndex, net_index: NetKeyIndex) -> None:
		self.publish(ConfigOpcode.APPKEY_ADD, AppKeyList.Add(net_index, app_index, new_key))

	def update(self, new_key: crypto.AppKey, app_index: AppKeyIndex, net_index: NetKeyIndex) -> None:
		self.publish(ConfigOpcode.APPKEY_UPDATE, AppKeyList.Update(net_index, app_index, new_key))

	def delete(self, app_index: AppKeyIndex, net_index: NetKeyIndex) -> None:
		self.publish(ConfigOpcode.APPKEY_DELETE, AppKeyList.Delete(net_index, app_index))

	def get(self, net_index: NetKeyIndex) -> None:
		self.publish(ConfigOpcode.APPKEY_GET, AppKeyList.Get(net_index))

	def check_status(self) -> None:
		if self.last_status != NetKeyStatus.Success:
			raise ValueError(f"bad status {self.last_status}")

	def on_list(self, msg: access.AccessMessage) -> None:
		new_list = AppKeyList.List.from_bytes(msg.payload)
		self.last_status = new_list.status
		self.check_status()
		self.key_index_list[new_list.net_key_index] = new_list.app_key_indexes

	def on_status(self, msg: access.AccessMessage):
		new_status = AppKeyList.Status.from_bytes(msg.payload)
		self.last_status = new_status.status
		self.check_status()


class ModelPublicationStateClient(SetStateClient):
	__slots__ = "model_publications"

	def __init__(self) -> None:
		super().__init__(ConfigOpcode.MODEL_PUBLICATION_GET, ConfigOpcode.MODEL_PUBLICATION_STATUS)
		self.model_publications: Dict[Tuple[UnicastAddress, access.ModelIdentifier], ModelPublication]
		self.last_status = foundation.Status.Success

	def set(self, value: foundation.ModelPublication, ack: Optional[bool] = True) -> None:
		assert ack
		opcode = ConfigOpcode.MODEL_PUBLICATION_SET if isinstance(value.publish_address,
																  UnicastAddress) else ConfigOpcode.MODEL_PUBLICATION_VIRTUAL_ADDRESS_SET
		self.publish(opcode, ModelPublication.Set(value))

	def check_status(self) -> None:
		if self.last_status != NetKeyStatus.Success:
			raise ValueError(f"bad status {self.last_status}")

	def on_status(self, msg: access.AccessMessage) -> None:
		new_status = ModelPublication.Status.from_bytes(msg.payload)
		self.last_status = new_status.status
		self.check_status()
		self.model_publications[new_status.model_publication.element_address,
								new_status.model_publication.model_identifier] = new_status.model_publication

	def get(self, element_address: UnicastAddress, model_identifier: access.ModelIdentifier) -> None:
		self.request_get(ModelPublication.Get(element_address, model_identifier))


class ModelSubscriptionStateClient(State):

	def __init__(self):
		super().__init__()
		self.last_status = foundation.Status.Success
		self.subscriptions: Dict[Tuple[UnicastAddress, access.ModelIdentifier], List[Address]] = dict()

	def check_status(self) -> None:
		if self.last_status != NetKeyStatus.Success:
			raise ValueError(f"bad status {self.last_status}")

	def on_list(self, new_list: ModelSubscription.List) -> None:
		self.last_status = new_list.status
		self.check_status()
		self.subscriptions[new_list.element_address, new_list.model_identifier] = new_list.addresses

	def delete(self, element_address: UnicastAddress, address: Union[VirtualAddress, GroupAddress],
			   model_identifier: access.ModelIdentifier) -> None:
		opcode = ConfigOpcode.MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_DELETE if isinstance(address, VirtualAddress) \
			else ConfigOpcode.MODEL_SUBSCRIPTION_DELETE
		self.publish(opcode, ModelSubscription.Delete(element_address, address, model_identifier))

	def delete_all(self, element_address: UnicastAddress, model_identifier: access.ModelIdentifier) -> None:
		self.publish(ConfigOpcode.MODEL_SUBSCRIPTION_DELETE_ALL,
					 ModelSubscription.DeleteAll(element_address, model_identifier))

	def add(self, element_address: UnicastAddress, address: Union[GroupAddress, VirtualAddress],
			model_identifier: access.ModelIdentifier) -> None:
		opcode = ConfigOpcode.MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_ADD if isinstance(address, VirtualAddress) \
			else ConfigOpcode.MODEL_SUBSCRIPTION_ADD
		self.publish(opcode, ModelSubscription.Add(element_address, address, model_identifier))

	def overwrite(self, element_address: UnicastAddress, address: Union[GroupAddress, VirtualAddress],
				  model_identifier: access.ModelIdentifier) -> None:
		opcode = ConfigOpcode.MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_OVERWRITE if isinstance(address, VirtualAddress) \
			else ConfigOpcode.MODEL_SUBSCRIPTION_OVERWRITE
		self.publish(opcode, ModelSubscription.Overwrite(element_address, address, model_identifier))

	def get(self, element_address: UnicastAddress, model_identifier: access.ModelIdentifier) -> None:
		opcode = ConfigOpcode.VENDOR_MODEL_SUBSCRIPTION_GET if model_identifier.company_id else \
			ConfigOpcode.SIG_MODEL_SUBSCRIPTION_GET
		self.publish(opcode, ModelSubscription.Get(element_address, model_identifier))


class ConfigClient(model.ModelClient):
	def __init__(self) -> None:
		super().__init__(config_client_id)
		self.network_beacon = SecureNetworkBeaconStateClient()
		self.add_state(self.network_beacon)
		self.relay = RelayStateClient()
		self.add_state(self.relay)
		self.app_key_list = AppKeyListStateClient()
		self.add_state(self.app_key_list)
		self.net_key_list = NetKeyListStateClient()
		self.add_state(self.net_key_list)
		self.model_publication = ModelPublicationStateClient()
		self.add_state(self.model_publication)
		self.model_subscription = ModelSubscriptionStateClient()

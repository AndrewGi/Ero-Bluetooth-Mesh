from .. import model
from .config_common import *


class SecureNetworkBeaconStateClient(SetStateClient):
	def __init__(self, initial_state: Optional[SecureBeaconState] = None) -> None:
		super().__init__(ConfigOpcode.BEACON_STATUS, ConfigOpcode.BEACON_GET, ConfigOpcode.BEACON_SET, None)
		self.state = initial_state

	def set(self, new_state: SecureBeaconState, ack: Optional[bool] = True) -> None:
		assert ack
		self.request_set_ack(Beacon.Set(new_state))

	def on_status(self, msg: access.AccessMessage) -> None:
		self.state = Beacon.Status.from_bytes(msg.payload)


class RelayStateClient(SetStateClient):
	FullState = Tuple[RelayState, RetransmitParameters]

	def __init__(self, initial_state: Optional[FullState] = None):
		super().__init__(ConfigOpcode.RELAY_STATUS, ConfigOpcode.RELAY_GET, ConfigOpcode.RELAY_SET, None)
		self.state = initial_state

	def set(self, new_state: FullState, ack: Optional[bool] = True) -> None:
		assert ack
		self.request_set_ack(Relay.Set(self.relay_state(), self.retransmit_parameters()))

	def relay_state(self) -> RelayState:
		return self.state[0]

	def retransmit_parameters(self) -> RetransmitParameters:
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


class ConfigClient(model.ModelClient):

	def __init__(self) -> None:
		super().__init__(config_client_id)
		self.network_beacon = SecureNetworkBeaconStateClient()
		self.relay = RelayStateClient()

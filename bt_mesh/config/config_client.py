from .. import model
from .config_common import *

class SecureNetworkBeaconStateClient(SetStateClient):
	def __init__(self, initial_state: Optional[SecureBeaconState]) -> None:
		super().__init__(ConfigOpcode.BEACON_STATUS, ConfigOpcode.BEACON_GET, ConfigOpcode.BEACON_SET, None)
		self.state = initial_state

	def set(self, new_state: SecureBeaconState, ack: Optional[bool] = True) -> None:
		assert ack
		self.request_set_ack(Beacon.Set(new_state))

	def on_status(self, msg: access.AccessMessage) -> None:
		self.state = Beacon.Status.from_bytes(msg.payload)

class RelayStateClient(SetStateClient):

	def __init__(self, initial_state: Optional[RelayState] = None):
		super().__init__(ConfigOpcode.RELAY_STATUS, ConfigOpcode.RELAY_GET, ConfigOpcode.RELAY_SET, None)
		self.state = initial_state

	def set(self, new_state: RelayState, ack: Optional[bool] = True) -> None:
		assert ack
		self.request_set_ack(RelayState.)

	def on_status(self, msg: access.AccessMessage) -> None:
		self.state = Relay.Status.from_bytes(msg.payload)


class ConfigClient(model.ModelClient):

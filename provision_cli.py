import json
from uuid import UUID
import sys

if __name__ == "__main__":
	from bt_mesh import mesh, prov, beacon, network, stack
	from bt_mesh.config import config_client
	from bt_mesh.bearers import bleson_bearer
	from bt_mesh.bearers.pb_adv import AdvBearer, Link, Links
else:
	from .bt_mesh import mesh, prov, beacon, network, stack
	from .bt_mesh.bearers.pb_adv import AdvBearer, Link, Links
	from .bt_mesh.config import config_client
	from .bt_mesh.bearers import bleson_bearer

from typing import *


class Session:

	def __init__(self, bearer: AdvBearer):
		self.bearer = bearer
		self.bearer.recv_beacon = self.handle_beacon
		self.provisioner = prov.Provisioner()
		self.links = Links(self.bearer)
		self.provisioner.unprovisioned_devices.on_new_device = self.on_new_device
		self.provisioner.failed_callback = self.on_provision_failed
		self.provisioner.get_provisioning_data = self.get_provisioning_data
		self.provisioner.on_provision_done = self.on_provision_done
		self.provision_all = False
		self.running = True
		self.mesh_network: Optional[network.Network] = None
		self.network_filename: Optional[str] = None
		self.target: Optional[mesh.Address] = None

		self.mesh_stack = stack.Stack(self.bearer, None)

		self.handlers: Dict[str, Callable[List[str]]] = dict()
		self.handlers["provision"] = self.cli_provision
		self.handlers["save_network"] = self.cli_save_network
		self.handlers["load_network"] = self.cli_load_network
		self.handlers["current_network"] = self.cli_current_network
		self.handlers["user_data"] = self.cli_user_data
		self.handlers["target"] = self.cli_target

		self.configure = ConfigCLI(self)
		self.handlers["config"] = self.configure.cli_handle

	def load_network(self, filename: str) -> None:
		self.info(f"loading network '{filename}")
		if self.mesh_network:
			self.warning("overwriting previously loaded network...")
		try:
			with open(filename, "r") as json_file:
				self.mesh_network = network.Network.from_dict(json.load(json_file))
		except FileNotFoundError as e:
			self.error(f"'{filename}' not found!")
		self.network_filename = filename
		self.mesh_stack.mesh_network = self.mesh_network
		self.good("loaded network")

	def save_network(self, filename: str) -> None:
		self.info(f"saving network to '{filename}'")
		if not self.mesh_network:
			self.error("no mesh network to save")
			return
		with open(filename, "w") as json_file:
			json.dump(self.mesh_network.to_dict(), json_file)
		self.network_filename = filename
		self.good("saved network")

	def on_new_device(self, new_device: prov.UnprovisionedDevice) -> None:
		self.info(f"new device! {new_device.device_uuid}")

	def get_provisioning_data(self, device: prov.UnprovisionedDevice) -> prov.ProvisioningData:
		remote_device = self.mesh_network.addresses.allocate_device(device.capabilities.number_of_elements)
		address = remote_device.primary_address
		net_id = device.user_data["network_id"]
		net_sm = self.mesh_network.global_context.get_net(net_id)
		network_key = net_sm.old.key
		ivi_index = self.mesh_network.global_context.iv_index
		flags = mesh.NetworkStateFlags(0)
		if self.mesh_network.global_context.iv_updating:
			flags |= mesh.NetworkStateFlags.IVUpdate
		if net_sm.phase == prov.crypto.KeyRefreshPhase.Phase2:
			network_key = net_sm.new
			flags |= mesh.NetworkStateFlags.KeyRefresh
		return prov.ProvisioningData(network_key, net_id, flags, ivi_index, address)

	def on_provision_failed(self, device: prov.UnprovisionedDevice) -> None:
		self.error(f"provisioned failed for {device.device_uuid}.Fail code: {device.failed_code}")

	def on_provision_done(self, device: prov.UnprovisionedDevice) -> None:
		self.good(f"{device.device_uuid} provisioned! primary_address: {device.primary_address}")

	def handle_beacon(self, new_beacon: beacon.Beacon) -> None:
		if new_beacon.beacon_type == beacon.BeaconType.UnprovisionedDevice:
			self.provisioner.handle_beacon(cast(beacon.UnprovisionedBeacon, new_beacon))

	def print_ansi(self, ansi_code: str, line: str) -> None:
		self.print(f"\033[{ansi_code}m{line}\033[0m")

	def warning(self, line: str) -> None:
		self.print_ansi("93", line)

	def error(self, line: str) -> None:
		self.print_ansi("91", line)

	def info(self, line: str) -> None:
		self.print_ansi("30;1", line)

	def good(self, line: str) -> None:
		self.print_ansi("32", line)

	def print(self, line: str) -> None:
		print(line)

	def provision(self, uuid: UUID, network_id: prov.crypto.NetKeyIndex) -> None:
		self.info(f"provisioning {uuid} to network {network_id.value}...")
		device = self.provisioner.unprovisioned_devices.get(uuid)
		device.set_bearer(self.links.new_link(uuid))
		device.user_data["network_id"] = network_id
		self.provisioner.provision(uuid)

	def cli_provision(self, args: List[str]) -> None:
		assert 1 <= len(args) <= 2
		uuid_bytes = int(args[0], base=16).to_bytes(byteorder="big", length=len(args[0]) // 2)
		if len(uuid_bytes) > 16:
			raise ValueError(f"expect 16 bytes got {len(uuid_bytes)}")
		network_id = prov.crypto.NetKeyIndex(int(args[1])) if len(args) >= 2 else prov.crypto.NetKeyIndex(0)
		uuid_bytes += b"\x00" * (16 - len(uuid_bytes))
		uuid = UUID(bytes=uuid_bytes)
		self.provision(uuid, network_id)

	def cli_load_network(self, args: List[str]) -> None:
		if len(args) > 1:
			self.error("too many args")
		filename = args[0] if args else self.network_filename
		if not filename:
			self.error("need a filename")
			return
		self.load_network(filename)

	def cli_save_network(self, args: List[str]) -> None:
		if len(args) > 1:
			self.error("too many args")
		filename = args[0] if args else self.network_filename
		if not filename:
			self.error("need a filename")
			return
		self.save_network(filename)

	def cli_current_network(self, args: List[str]) -> None:
		if args:
			self.error("too many args")
		self.info(f"filename: {self.network_filename}")
		self.info(f"json: {self.mesh_network.to_dict()}")

	def handle_line(self, line: str) -> None:
		self.handle_args(line.split())

	def handle_args(self, args: List[str]) -> None:
		if not args:
			return
		func = None
		try:
			func = self.handlers[args[0]]
		except KeyError:
			self.error(f"unrecognized command '{args}'")
			return
		if func is None:
			return
		func(args[1:])

	def cli_target(self, args: List[str]) -> None:
		def print_target():
			self.good(f"target: {self.target}")
		if len(args) == 0:
			print_target()
			return
		if len(args) == 1:
			new_target = args[0]
			if new_target.lower() == "none":
				self.target = None
				print_target()
				return
			self.target = mesh.Address.from_str(new_target)
		print_target()



	def cli_user_data(self, args: List[str]) -> None:
		if not self.target:
			self.error("no target")
			return
		try:
			device: network.RemoteDevice = self.mesh_network.addresses.unicasts[self.target]
		except KeyError:
			self.error(f"target {self.target} does not exist in local network")
			return
		if len(args) == 0:
			self.good(f"{self.target}:{device.user_data}")
			return
		key = args[0]

		if len(args) > 1:
			new_value = " ".join(args[1:])
			def set_net_value() -> None:
				if new_value.lower() == "none":
					del device.user_data[key]
				if new_value[0] == '"' and new_value[-1] == '"':
					device.user_data[key] = new_value
					return
				try:
					device.user_data[key] = int(new_value)
					return
				except ValueError:
					pass
				try:
					device.user_data[key] = int(new_value, base=16)
					return
				except ValueError:
					pass
				try:
					device.user_data[key] = float(new_value)
					return
				except ValueError:
					pass
				raise ValueError(f"unknown format: {new_value}")

			set_net_value()

		value = None
		try:
			value = device.user_data[key]
		except KeyError:
			pass
		self.good(f"{self.target}:{key}:{value}")



class CLIHandler:
	def __init__(self, name: str, session: Session) -> None:
		self.name = name
		self.session = session
		self.handlers: Dict[str, Callable[List[str]]] = dict()
		self.session.handlers[self.name] = self.cli_handle


	def cli_handle(self, args: List[str]) -> None:
		if not args:
			return
		func = None
		try:
			func = self.handlers[args[0]]
		except KeyError:
			self.session.error(f"{self.name}: unrecognized command '{args}'")
			self.session.error(f"{self.name}: unrecognized command '{args}'")
			return
		if func is None:
			return
		func(args[1:])

class ConfigCLI(CLIHandler):
	def __init__(self, session: Session) -> None:
		super().__init__("config", session)
		self.configure_client = config_client.ConfigClient()

	def cli_handle(self, args: List[str]) -> None:
		pass

	def relay_get(self) -> None:
		if not self.session.target:
			self.session.error("no target")
			return
		self.configure_client.target(cast(mesh.UnicastAddress, self.session.target), dev_key=True)
		self.session.info("requesting relay status...")
		self.configure_client.relay.request_get()
		self.configure_client.relay.status_condition.wait()
		self.session.good(f"relay status: {self.configure_client.relay.state}")

	def cli_relay(self, args: List[str]) -> None:
		assert len(args) == 0
		self.relay_get()



def main() -> None:
	if __name__ == "__main__":
		from bt_mesh.bearers import bleson_bearer
	else:
		from .bt_mesh.bearers import bleson_bearer

	bearer = bleson_bearer.BlesonBearer()
	session = Session(bearer)
	session.mesh_network = network.Network.new()
	session.mesh_stack.mesh_network = session.mesh_network
	if len(sys.argv) > 1:
		if sys.argv[1] == "-pall":
			session.provision_all = True
	session.info("ready")
	while session.running:
		line = input()
		session.handle_line(line)


if __name__ == "__main__":
	main()

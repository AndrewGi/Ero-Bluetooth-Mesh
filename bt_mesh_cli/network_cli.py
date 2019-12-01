from typing import List, Optional
import json

from bt_mesh import mesh, network

from session import Session, CLIHandler, between_n_args


class NetworkCLI(CLIHandler):
	def __init__(self, session: Session) -> None:
		super().__init__("network", session)
		self.network_filename: Optional[str] = None
		self.add_cli(GroupCLI(session))

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
		self.info(f"json: {self.network().to_dict()}")

	def load_network(self, filename: str) -> None:
		self.info(f"loading network '{filename}")
		try:
			with open(filename) as json_file:
				mesh_network = network.Network.from_dict(json.load(json_file))
				self.network().crypto_context = mesh_network.crypto_context
				self.network().addresses = mesh_network.addresses
		except FileNotFoundError as e:
			self.error(f"'{filename}' not found!")
		self.network_filename = filename
		self.stack().mesh_network = self.network()
		self.good(f"loaded '{filename}' network")

	def save_network(self, filename: str) -> None:
		self.info(f"saving network to '{filename}'")
		with open(filename, "w") as json_file:
			json.dump(self.network().to_dict(), json_file)
		self.network_filename = filename
		self.good(f"saved network to '{filename}'")



	def cli_user_data(self, args: List[str]) -> None:
		if not self.target():
			self.error("no target")
			return
		try:
			device: network.RemoteDevice = self.network().addresses.unicasts[self.session.target]
		except KeyError:
			self.session.error(f"target {self.session.target} does not exist in local network")
			return
		if len(args) == 0:
			self.session.good(f"{self.session.target}:{device.user_data}")
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

class NetKeyCLI(CLIHandler):
	def __init__(self, session: Session) -> None:
		super().__init__("netkey", session)

	def list(self) -> None:
		for net in self.network().crypto_context.nets.values():
			self.good(f"index {net.index} phase: {net.phase}")

	@between_n_args(0)
	def cli_list(self, args: List[str]) -> None:
		self.list()

	def get(self, index: mesh.NetKeyIndex) -> None:
		cc = self.network().crypto_context
		if index not in cc.nets:
			self.error(f"index {index} not found in netkey list")
			return
		net = cc.get_net(index)
		self.good()


class GroupCLI(CLIHandler):
	def __init__(self, session: Session) -> None:
		super().__init__("group", session)
		self.add_handler("add", self.cli_group_add)
		self.add_handler("list", self.cli_list_group)
		self.add_handler("get", self.cli_group_get)
		self.add_handler("help", self.cli_group_help)

	@between_n_args(0, 1)
	def cli_group_help(self, args: List[str]) -> None:
		self.session.good(
			"""
add [group_name] (group_address)	add a group (leave address blank for random)
list								list all groups
get	[group_name]					get group
help								list group help
"""[1:-1])

	def get_group(self, name: str) -> None:
		try:
			address = self.network().addresses.get_group(name)
		except KeyError:
			self.session.warning(f"'{name}' group not found")
			return
		else:
			self.session.good(f"{name} : {address}")

	@between_n_args(1, 2)
	def cli_group_get(self, args: List[str]) -> None:
		self.get_group(args[0])

	def add_group(self, name: str, address: Optional[mesh.GroupAddress] = None) -> None:
		if address is None:
			address = self.network().addresses.add_random_group(name)
		else:
			self.network().addresses.add_group(address, name)
		self.session.good(f"added group '{name}' : '{address}'")

	@between_n_args(1, 3)
	def cli_group_add(self, args: List[str]) -> None:
		address: Optional[mesh.Address] = None
		if len(args) == 2:
			address = mesh.Address.from_str(args[1])
			if not isinstance(address, mesh.GroupAddress):
				self.session.error(f"expect group address not {address.__class__}")
				return
		name = args[0]
		self.add_group(name, address)

	def list_groups(self) -> None:
		self.session.good(str(self.network().addresses.groups))

	@between_n_args(0, 1)
	def cli_list_group(self, args: List[str]) -> None:
		self.list_groups()


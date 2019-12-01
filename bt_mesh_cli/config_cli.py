import abc
from typing import List, Optional, cast

from bt_mesh import mesh, crypto
from bt_mesh.config import config_client

from session import Session, CLIHandler, between_n_args


class ConfigCLI(CLIHandler):
	# Support:
	def __init__(self, session: Session) -> None:
		super().__init__("config", session)
		self.configure_client = config_client.ConfigClient()

		self.add_cli(RelayCLI(self))
		self.add_cli(NetKeyCLI(self))
		self.add_cli(BeaconCLI(self))
		self.add_cli(CompositionPageCLI(self))
		self.add_cli(DefaultTTLCLI(self))

		self.add_handler("help", self.cli_help)

	def set_target(self) -> bool:
		if not self.session.target:
			self.error("no target")
			return False
		if self.session.bearer is not None:
			self.configure_client.target(cast(mesh.UnicastAddress, self.session.target), dev_key=True)
			return True
		else:
			self.session.warning("no bearer! can't set config target")
			return False

	@between_n_args(0, 1)
	def cli_help(self, args: List[str]) -> None:
		self.list_help()

	def list_help(self) -> None:
		self.session.good(
			"""
help	list help
relay	config relay state
netkey	config netkey list
beacon 	config secure beacon state
composition get and check data composition page
"""[1:-1]
		)


class RelayCLI(CLIHandler):
	def __init__(self, config_cli: ConfigCLI) -> None:
		super().__init__("relay", config_cli.session)
		self.client = config_cli
		self.timeout = 10
		self.model = config_cli.configure_client.relay
		self.add_handler("help", self.cli_help)
		self.add_handler("get", self.cli_get)
		self.add_handler("set", self.cli_set)
		self.add_handler("check", self.cli_check)

	@between_n_args(0)
	def cli_help(self, args: List[str]) -> None:
		self.list_help()

	def list_help(self) -> None:
		self.good(
"""
help						list relay help
get							get relay status
set [state] [count] [step] 	set relay status
check						reports the currently known state
"""[1:-1]
		)

	def relay_get(self) -> None:
		if not self.client.set_target():
			return
		self.info(f"requesting f{self.name} status...")
		self.model.request_get()
		self.model.status_condition.wait(self.timeout)
		self.good(f"f{self.name} status: {self.model.state}")

	@between_n_args(0, 1)
	def cli_get(self, args: List[str]) -> None:
		self.relay_get()

	def set(self, new_state: config_client.RelayState,
			retransmit_parameters: mesh.RelayRetransmitParameters) -> None:

		if not self.client.set_target():
			return
		self.info(f"setting {self.name} state...")
		self.model.set((new_state, retransmit_parameters))
		self.model.status_condition.wait(self.timeout)
		self.good(f"{self.name} status: {self.model.state}")

	@between_n_args(3, 4)
	def cli_set(self, args: List[str]) -> None:
		state: Optional[config_client.RelayState] = None
		retransmit_parameters: Optional[mesh.RelayRetransmitParameters] = None
		try:
			state = config_client.RelayState(int(args[0]))
		except ValueError as e:
			self.error(f"invalid {self.name} state {args[0]}")
			return
		finally:
			count = int(args[1])
			step = int(args[2])
			try:
				retransmit_parameters = mesh.RelayRetransmitParameters(count, step)
			except ValueError as e:
				self.error(f"invalid retransmit parameters ({count}, {step})")
				return
			finally:
				assert state is not None and retransmit_parameters is not None
				self.set(state, retransmit_parameters)

	@between_n_args(0)
	def cli_check(self, args: List[str]) -> None:
		self.check()

	def check(self) -> None:
		if self.target() is None:
			self.error("no target set")
			return
		self.good(f"{self.name} state: {self.model.state}")


class BeaconCLI(CLIHandler):
	def __init__(self, config_cli: ConfigCLI) -> None:
		super().__init__("beacon", config_cli.session)
		self.client = config_cli
		self.timeout = 10
		self.model = config_cli.configure_client.network_beacon
		self.add_handler("help", self.cli_help)
		self.add_handler("get", self.cli_get)
		self.add_handler("set", self.cli_set)
		self.add_handler("check", self.cli_check)

	@between_n_args(0)
	def cli_help(self, args: List[str]) -> None:
		self.list_help()

	def list_help(self) -> None:
		self.good(
			"""
help			list beacon help
get				get beacon status
set [state] 	set beacon status
check			reports the currently known state
"""[1:-1]
		)

	def get(self) -> None:
		if not self.client.set_target():
			return
		self.info(f"requesting f{self.name} status...")
		self.model.request_get()
		self.model.status_condition.wait(self.timeout)
		self.good(f"f{self.name} status: {self.model.state}")

	@between_n_args(0, 1)
	def cli_get(self, args: List[str]) -> None:
		self.get()

	def set(self, new_state: config_client.SecureBeaconState) -> None:

		if not self.client.set_target():
			return
		self.info(f"setting {self.name} state...")
		self.model.set(new_state)
		self.model.status_condition.wait(self.timeout)
		self.good(f"{self.name} status: {self.model.state}")

	@between_n_args(3, 4)
	def cli_set(self, args: List[str]) -> None:
		state: Optional[config_client.SecureBeaconState] = None
		try:
			state = config_client.SecureBeaconState(int(args[0]))
		except ValueError as e:
			self.error(f"invalid {self.name} state {args[0]}")
			return
		finally:
			assert state is not None
			self.set(state)

	@between_n_args(0)
	def cli_check(self, args: List[str]) -> None:
		self.check()

	def check(self) -> None:
		if self.target() is None:
			self.error("no target set")
			return
		self.good(f"{self.name} state: {self.model.state}")


class NetKeyCLI(CLIHandler):
	def __init__(self, config_cli: ConfigCLI) -> None:
		super().__init__("netkey", config_cli.session)
		self.client = config_cli
		self.timeout = 10
		self.model = config_cli.configure_client.net_key_list
		self.add_handler("help", self.cli_help)
		self.add_handler("add", self.cli_add)
		self.add_handler("get", self.cli_get)
		self.add_handler("check", self.cli_check)

	@between_n_args(0)
	def cli_help(self, args: List[str]) -> None:
		self.list_help()

	def list_help(self) -> None:
		self.good(
			"""
			help						list relay help
			get							get full netkey list
			add [netkey_index]			add netkey to list
			check						reports the currently known list
			"""[1:-1]
		)

	def add(self, new_key: crypto.NetworkKey, index: mesh.NetKeyIndex) -> None:
		if not self.client.set_target():
			return
		self.session.info("adding netkey...")
		self.model.add(new_key, index)
		self.model.status_condition.wait(self.timeout)
		self.session.good("added netkey")

	@between_n_args(1)
	def cli_add(self, args: List[str]) -> None:
		index = mesh.NetKeyIndex(int(args[0]))
		key: Optional[crypto.NetworkKey] = None
		try:
			key = self.network().crypto_context.get_net(index).tx_sm().key
		except KeyError as e:
			self.session.error(f"netkey index '{index}' does not exist")
		finally:
			assert key is not None
			self.add(key, index)

	def get(self) -> None:
		if not self.client.set_target():
			return
		self.info("getting netkey list...")
		self.model.get()
		self.model.list_condition.wait(self.timeout)
		self.check()

	@between_n_args(0)
	def cli_get(self, args: List[str]) -> None:
		self.get()

	@between_n_args(0)
	def cli_check(self, args: List[str]) -> None:
		self.check()

	def check(self) -> None:
		self.good(f"netkey list: {self.model.key_index_list}")


class CompositionPageCLI(CLIHandler):
	def __init__(self, config_cli: ConfigCLI) -> None:
		super().__init__("composition", config_cli.session)
		self.client = config_cli
		self.timeout = 10
		self.model = config_cli.configure_client.composition
		self.add_handler("help", self.cli_help)
		self.add_handler("get", self.cli_get)
		self.add_handler("check", self.cli_check)

	@between_n_args(0)
	def cli_help(self, args: List[str]) -> None:
		self.list_help()

	def list_help(self) -> None:
		self.good(
			"""
help			list composition data help
get	[page_num]	get composition data page (only page 0 for now) 
check			reports the currently known composition data page
"""[1:-1]
		)

	def get(self, page_num: mesh.U8) -> None:
		if page_num.value != 0:
			self.error(f"unknown data page: {page_num}")
			return
		if not self.client.set_target():
			return
		self.info(f"requesting f{self.name} status...")
		self.model.request_get()
		self.model.status_condition.wait(self.timeout)
		self.good(f"f{self.name} status: {self.model.state}")

	@between_n_args(1)
	def cli_get(self, args: List[str]) -> None:
		try:
			page_num = mesh.U8(int(args[0]))
		except ValueError as e:
			self.error(f"invalid page number: {args[0]}")
			return
		self.get(page_num)


	@between_n_args(0)
	def cli_check(self, args: List[str]) -> None:
		self.check()

	def check(self) -> None:
		if self.target() is None:
			self.error("no target set")
			return
		self.good(f"{self.name} state: {self.model.state}")


class DefaultTTLCLI(CLIHandler):
	def __init__(self, config_cli: ConfigCLI) -> None:
		super().__init__("ttl", config_cli.session)
		self.client = config_cli
		self.timeout = 10
		self.model = config_cli.configure_client.default_ttl
		self.add_handler("help", self.cli_help)
		self.add_handler("get", self.cli_get)
		self.add_handler("set", self.cli_set)
		self.add_handler("check", self.cli_check)

	@between_n_args(0)
	def cli_help(self, args: List[str]) -> None:
		self.list_help()

	def list_help(self) -> None:
		self.good(
			"""
help			list default ttl help
get				get default ttl
set [ttl] 		set default ttl
check			reports the currently known default ttl
"""[1:-1]
		)

	def get(self) -> None:
		if not self.client.set_target():
			return
		self.info(f"requesting f{self.name} status...")
		self.model.request_get()
		self.model.status_condition.wait(self.timeout)
		self.good(f"f{self.name} status: {self.model.state}")

	@between_n_args(0, 1)
	def cli_get(self, args: List[str]) -> None:
		self.get()

	def set(self, new_state: mesh.TTL) -> None:
		if not self.client.set_target():
			return
		self.info(f"setting {self.name} state...")
		self.model.set(new_state)
		self.model.status_condition.wait(self.timeout)
		self.good(f"{self.name} status: {self.model.state}")

	@between_n_args(3, 4)
	def cli_set(self, args: List[str]) -> None:
		ttl = Optional[mesh.TTL] = None
		try:
			ttl = mesh.TTL(int(args[0]))
		except ValueError as e:
			self.error(f"invalid {self.name} ttl {args[0]}")
			return
		finally:
			assert ttl is not None
			self.set(ttl)

	@between_n_args(0)
	def cli_check(self, args: List[str]) -> None:
		self.check()

	def check(self) -> None:
		if self.target() is None:
			self.error("no target set")
			return
		self.good(f"{self.name} state: {self.model.state}")


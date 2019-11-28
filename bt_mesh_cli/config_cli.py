
class ConfigCLI(CLIHandler):
	# Support:
	def __init__(self, session: Session) -> None:
		super().__init__("config", session)
		self.configure_client = config_client.ConfigClient()

		self.add_handler("relay_check")
		self.add_handler("relay_get", self.cli_relay_get)
		self.add_handler("relay_set", self.cli_relay_set)

		self.add_handler("help", self.cli_help)

	def set_target(self) -> bool:
		if not self.session.target:
			self.session.error("no target")
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
help												list help
relay_get											get relay status
relay_set [state] [retrans_count] [retrans_step]	set relay status
"""[1:-1]
		)

	def relay_get(self) -> None:
		if not self.set_target():
			return
		self.session.info("requesting relay status...")
		self.configure_client.relay.request_get()
		self.configure_client.relay.status_condition.wait()
		self.session.good(f"relay status: {self.configure_client.relay.state}")

	@between_n_args(0, 1)
	def cli_relay_get(self, args: List[str]) -> None:
		self.relay_get()

	def relay_set(self, new_state: config_client.RelayState,
				  retransmit_parameters: mesh.RelayRetransmitParameters) -> None:

		if not self.set_target():
			return
		self.session.info("setting relay state...")
		self.configure_client.relay.set((new_state, retransmit_parameters))
		self.configure_client.relay.status_condition.wait()
		self.session.good(f"relay status: {self.configure_client.relay.state}")

	@between_n_args(3, 4)
	def cli_relay_set(self, args: List[str]) -> None:
		state: Optional[config_client.RelayState] = None
		retransmit_parameters: Optional[mesh.RelayRetransmitParameters] = None
		try:
			state = config_client.RelayState(int(args[0]))
		except ValueError as e:
			self.session.error(f"invalid relay state {args[0]}")
			return
		finally:
			count = int(args[1])
			step = int(args[2])
			try:
				retransmit_parameters = mesh.RelayRetransmitParameters(count, step)
			except ValueError as e:
				self.session.error(f"invalid retransmit parameters ({count}, {step})")
				return
			finally:
				assert state is not None and retransmit_parameters is not None
				self.relay_set(state, retransmit_parameters)

	def netkey_add(self, new_key: crypto.NetworkKey, index: mesh.NetKeyIndex) -> None:
		if not self.set_target():
			return
		self.session.info("adding netkey...")
		self.configure_client.net_key_list.add(new_key, index)
		self.configure_client.net_key_list.status_condition.wait()
		self.session.good("added netkey")

	@between_n_args(1)
	def cli_netkey_add(self, args: List[str]) -> None:
		index = mesh.NetKeyIndex(int(args[0]))
		key: Optional[crypto.NetworkKey] = None
		try:
			key = self.session.mesh_network.global_context.get_net(index).tx_sm().key
		except KeyError as e:
			self.session.error(f"netkey index '{index}' does not exist")
		finally:
			assert key is not None
			self.netkey_add(key, index)

	def netkey_get(self) -> None:
		if not self.set_target():
			return
		self.session.info("getting netkey list...")
		self.configure_client.net_key_list.get()
		self.configure_client.net_key_list.list_condition.wait()
		self.session.good(f"netkey list: {self.configure_client.net_key_list.key_index_list}")

	@between_n_args(0)
	def cli_netkey_get(self, args: List[str]) -> None:
		self.netkey_get()
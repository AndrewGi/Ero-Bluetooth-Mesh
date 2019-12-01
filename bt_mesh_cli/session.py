import json
from typing import List, Optional, Dict, Callable

from bt_mesh import mesh, network, stack, crypto, beacon
from bt_mesh.bearers.pb_adv import AdvBearer


def between_n_args(low: int, high: Optional[int] = None):
	if high is None:
		high = low + 1

	def wrapper(f):
		def wrapped_func(self, args: List[str]):
			if low <= len(args) < high:
				return f(self, args)
			else:
				output = f"wrong args for {f.__name__}: {low}<={len(args)}<{high}"
				if hasattr(self, "session"):
					self.session.error(output)
				elif hasattr(self, "error"):
					self.error(output)
				else:
					raise ValueError(output)

		return wrapped_func

	return wrapper


class Target:
	def __init__(self, address: mesh.Address, net_key_index: mesh.NetKeyIndex, app_key_index: mesh.AppKeyIndex) -> None:
		self.address = address
		self.net_key_index = net_key_index
		self.app_key_index = app_key_index

	def __repr__(self) -> str:
		return f"Target({self.address}, {self.net_key_index}, {self.app_key_index})"


class Session:

	def __init__(self, bearer: Optional[AdvBearer]):
		self.bearer = bearer

		self.running = True
		self.target: Optional[mesh.Address] = None

		self.mesh_stack = stack.Stack(self.bearer, stack.LocalContext.new(), network.Network.new())
		self.secure_network_beacons = beacon.SecureBeacons()

		self.handlers: Dict[str, Callable[[List[str],], None]] = dict()
		self.handlers["target"] = self.cli_target
		self.handlers["dump"] = self.cli_dump
		self.handlers["quit"] = self.cli_quit
		self.handlers["help"] = self.cli_help


	def add_cli(self, cli_handler: 'CLIHandler') -> None:
		if cli_handler.name in self.handlers:
			raise NameError(f"{cli_handler.name} already exists in handlers: {self.handlers.keys()}")
		self.handlers[cli_handler.name] = cli_handler.cli_handle

	def list_help(self) -> None:
		self.good(
			"""
help										list help
config										config client commands
group										local group commands
target [address] [net_index] [app_index]	set the target of any remote commands
save_network (filename)						save network to json file (will use last filename if none given)
load_network (filename)						load network from json file (will use last filename if none given)
user_data [key] [user_data]					assigns user_data to current target
quit										quit the program without saving
"""[1:-1])

	@between_n_args(0)
	def cli_help(self, args: List[str]) -> None:
		self.list_help()

	@between_n_args(0)
	def cli_quit(self, args: List[str]) -> None:
		self.good("quitting...")
		self.mesh_stack.stop()
		self.running = False




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

	def handle_line(self, line: str) -> None:
		self.handle_args(line.split())

	def handle_args(self, args: List[str]) -> None:
		if not args:
			return
		try:
			func = self.handlers[args[0]]
		except KeyError:
			self.error(f"unrecognized command '{args}'")
			return
		else:
			func(args[1:])

	@between_n_args(3)
	def cli_target(self, args: List[str]) -> None:
		def print_target():
			nonlocal self
			self.good(f"target: {self.target}")

		if len(args) == 0:
			print_target()
			return
		if len(args) == 1 and args[0].lower() == "none":
			self.target = None
			print_target()
			return

		if len(args) != 3:
			self.error("expected 3 args for target (target_address, net_key_index, app_key_index)")
			return
		new_address = mesh.Address.from_str(args[0])
		net_key_index = mesh.NetKeyIndex(int(args[1], base=16) if args[1].startswith("0x") else int(args[1]))
		app_key_index = mesh.AppKeyIndex(int(args[2], base=16) if args[1].startswith("0x") else int(args[2]))
		self.target = Target(new_address, net_key_index, app_key_index)
		print_target()

	@staticmethod
	def pretty_dump(o: mesh.ToDict) -> str:
		return json.dumps(o.to_dict(), indent=2, sort_keys=True)

	@between_n_args(1)
	def cli_dump(self, args: List[str]) -> None:
		options = {
			"stack": self.mesh_stack,
			"network": self.mesh_stack.mesh_network,
			"crypto": self.mesh_stack.mesh_network.crypto_context,
			"local": self.mesh_stack.local_context

		}
		result = options.get(args[0])
		if result is None:
			self.error(f"option {args[0]} not found")
			return
		self.good(self.pretty_dump(result))


class CLIHandler:
	def __init__(self, name: str, session: Session) -> None:
		self.name = name
		self.session = session
		self.handlers: Dict[str, Callable[[List[str], ], None]] = dict()

	def target(self) -> Optional[Target]:
		return self.session.target

	def cli_handle(self, args: List[str]) -> None:
		if not args:
			return
		try:
			func = self.handlers[args[0]]
		except KeyError:
			self.session.error(f"{self.name}: unrecognized command '{args}'")
			return
		else:
			try:
				func(args[1:])
			except KeyError as ke:
				self.error(f"key error: {ke}")
			except ValueError as ve:
				self.error(f"value error: {ve}")

	def add_handler(self, name: str, handler: Callable[[List[str]], None]) -> None:
		if name in self.handlers:
			raise RuntimeError(f"{name} already being used")
		self.handlers[name] = handler

	def add_cli(self, cli_handler: 'CLIHandler') -> None:
		self.add_handler(cli_handler.name, cli_handler.cli_handle)

	def info(self, message: str) -> None:
		self.session.info(f"{self.name}: {message}")

	def warning(self, message: str) -> None:
		self.session.warning(f"{self.name}: {message}")

	def good(self, message: str) -> None:
		self.session.good(f"{self.name}: {message}")

	def error(self, message: str) -> None:
		self.session.error(f"{self.name}: {message}")

	def stack(self) -> stack.Stack:
		return self.session.mesh_stack

	def network(self) -> network.Network:
		return self.session.mesh_stack.mesh_network

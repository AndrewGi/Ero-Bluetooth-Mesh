import sys
from typing import *

from bt_mesh import bearer

from session import Session
import config_cli
import network_cli
import provision_cli


def main() -> None:
	print("running main...")
	bt_bearer: Optional[bearer.Bearer] = None
	dummy = "-dummy" in sys.argv[1:]

	if not dummy:
		if sys.platform.startswith('linux'):
			from bt_mesh.bearers import bleson_bearer
			bt_bearer = bleson_bearer.BlesonBearer()
		else:
			print("unsupported platform: " + sys.platform)
	else:
		print("using dummy bearer")
		from bt_mesh.bearers import dummy
		bt_bearer = dummy.DummyBearer()
	print("bearer ready")

	session = Session(bt_bearer)
	session.add_cli(network_cli.NetworkCLI(session))
	session.add_cli(provision_cli.ProvisionerCLI(session))
	session.add_cli(config_cli.ConfigCLI(session))

	session.info("ready")
	while session.running:
		line = input()
		session.handle_line(line)
	session.good("goodbye")


if __name__ == "__main__":
	main()

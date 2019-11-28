from typing import *

from ..bt_mesh import mesh

from .session import CLIHandler, between_n_args



def main() -> None:
	print("running main...")
	bearer: Optional[Bearer] = None
	if sys.platform.startswith('linux'):
		if __name__ == "__main__":
			from bt_mesh.bearers import bleson_bearer
		else:
			from .bt_mesh.bearers import bleson_bearer
		bearer = bleson_bearer.BlesonBearer()
	else:
		print("unsupported platform: " + sys.platform)
	print("bearer ready")
	session = Session(bearer)
	if len(sys.argv) > 1:
		if sys.argv[1] == "-pall":
			session.provision_all = True
	session.info("ready")
	while session.running:
		line = input()
		session.handle_line(line)
	session.good("goodbye")


if __name__ == "__main__":
	main()

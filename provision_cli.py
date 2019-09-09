from uuid import UUID
import sys
if __name__ == "__main__":
	from bt_mesh import mesh, prov, beacon
	from bt_mesh.config import config_client
	from bt_mesh.bearers import bleson_bearer
	from bt_mesh.bearers.pb_adv import AdvBearer, Link
else:
	from .bt_mesh import mesh, prov, beacon
	from .bt_mesh.bearers.pb_adv import AdvBearer, Link
	from .bt_mesh.config import config_client
	from .bt_mesh.bearers import bleson_bearer

from typing import *


class Session:

	def __init__(self, bearer: AdvBearer):
		self.bearer = bearer
		self.bearer.recv_beacon = self.handle_beacon
		self.provisioner = prov.Provisioner()
		self.provisioner.unprovisioned_devices.on_new_device = self.on_new_device
		self.provision_all = False
		self.running = True

	def on_new_device(self, new_device: prov.UnprovisionedDevice) -> None:
		self.print(f"new device! {new_device.device_uuid}")
		if self.provision_all:
			self.provision(new_device.device_uuid)

	def on_provision_failed(self, device: prov.UnprovisionedDevice) -> None:
		self.print(f"provisioned failed for {device.device_uuid}")

	def handle_beacon(self, new_beacon: beacon.Beacon) -> None:
		if new_beacon.beacon_type == beacon.BeaconType.UnprovisionedDevice:
			self.provisioner.handle_beacon(cast(beacon.UnprovisionedBeacon, new_beacon))

	def print(self, line: str) -> None:
		print(line)

	def provision(self, uuid: UUID) -> None:
		self.print(f"provisioning {uuid}...")
		device = self.provisioner.unprovisioned_devices.get(uuid)
		device.failed_callback = self.on_provision_failed
		Link.set_link(device, self.bearer)
		self.provisioner.provision(uuid)
		with device.event_condition:
			device.event_condition.wait(device.done)

	def cli_provision(self, args: List[str]) -> None:
		assert len(args) == 1
		uuid_bytes = int(args[0], base=16).to_bytes(byteorder="big", length=len(args[0])//2)
		if len(uuid_bytes)>16:
			raise ValueError(f"expect 16 bytes got {len(uuid_bytes)}")
		uuid_bytes += b"\x00" * (16 - len(uuid_bytes))
		uuid = UUID(bytes=uuid_bytes)
		self.provision(uuid)

	def handle_line(self, line: str) -> None:
		self.handle_args(line.split())

	def handle_args(self, args: List[str]) -> None:
		if args[0] == "provision":
			self.cli_provision(args[1:])
		else:
			self.print(f"unrecognized command {args}")


class CLIHandler:
	def __init__(self, session: Session) -> None:
		self.session = session
		self.handlers: Dict[str, Callable[List[str]]] = dict()


class ConfigCLI(CLIHandler):
	def __init__(self, session: Session) -> None:
		super().__init__(session)
		self.configure_client = config_client.ConfigClient()

	def relay_get(self) -> None:
		self.configure_client.relay.request_get()
		self.configure_client.relay.status_condition.wait()
		self.session.print(self.configure_client.relay.state)

	def cli_relay(self, args: List[str]):
		assert len(args) == 0
		self.relay_get()


def main() -> None:
	if __name__ == "__main__":
		from bt_mesh.bearers import bleson_bearer
	else:
		from .bt_mesh.bearers import bleson_bearer

	bearer = bleson_bearer.BlesonBearer()
	session = Session(bearer)
	if sys.argv[1] == "-pall":
		session.provision_all = True
	print("ready")
	while session.running:
		line = input()
		session.handle_line(line)


if __name__ == "__main__":
	main()

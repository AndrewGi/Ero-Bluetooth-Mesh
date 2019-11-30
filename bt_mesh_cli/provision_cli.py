from uuid import UUID
from typing import List, cast

from bt_mesh import mesh, prov, beacon
from bt_mesh.bearers import pb_adv

from session import Session, CLIHandler, between_n_args


class ProvisionerCLI(CLIHandler):
	def provision(self, uuid: UUID, network_index: prov.crypto.NetKeyIndex) -> None:
		self.session.info(f"provisioning {uuid} to network {network_index.value}...")
		device = self.provisioner.unprovisioned_devices.get(uuid)
		device.set_bearer(self.links.new_link(uuid))
		device.user_data["network_index"] = network_index
		self.provisioner.provision(uuid)
		self.provisioner.unprovisioned_devices.on_new_device = self.on_new_device
		self.provisioner.failed_callback = self.on_provision_failed
		self.provisioner.get_provisioning_data = self.get_provisioning_data
		self.provisioner.on_provision_done = self.on_provision_done
		if self.session.bearer:
			self.session.bearer.recv_beacon = self.handle_beacon

	@between_n_args(1, 3)
	def cli_provision(self, args: List[str]) -> None:
		assert 1 <= len(args) <= 2
		uuid_bytes = int(args[0], base=16).to_bytes(byteorder="big", length=len(args[0]) // 2)
		if len(uuid_bytes) > 16:
			raise ValueError(f"expect 16 bytes got {len(uuid_bytes)}")
		network_index = prov.crypto.NetKeyIndex(int(args[1])) if len(args) >= 2 else prov.crypto.NetKeyIndex(0)
		uuid_bytes += b"\x00" * (16 - len(uuid_bytes))
		uuid = UUID(bytes=uuid_bytes)
		self.provision(uuid, network_index)

	def on_new_device(self, new_device: prov.UnprovisionedDevice) -> None:
		self.info(f"new device! {new_device.device_uuid}")

	def get_provisioning_data(self, device: prov.UnprovisionedDevice) -> prov.ProvisioningData:
		remote_device = self.network().addresses.allocate_device(device.capabilities.number_of_elements)
		address = remote_device.primary_address
		net_id = device.user_data["network_index"]
		net_sm = self.network().global_context.get_net(net_id)
		network_key = net_sm.old.key
		ivi_index = self.network().global_context.iv_index
		flags = mesh.NetworkStateFlags(0)
		if self.network().global_context.iv_updating:
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
		elif new_beacon.beacon_type == beacon.BeaconType.SecureNetwork:
			self.secure_network_beacons.handle_beacon(cast(beacon.SecureBeacon, new_beacon))

	def __init__(self, session: Session) -> None:
		super().__init__("provision", session)
		self.provisioner = prov.Provisioner()
		self.links = pb_adv.Links(self.session.bearer)

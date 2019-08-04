import time

from bt_mesh import network
from bt_mesh.bearers import bleson_bearer, pb_adv
print("starting")

network = network.Network()
network.add_bearer(bleson_bearer.BlesonBearer())
while True:
	print(network.provisioner.unprovisioned_devices)
	if len(network.provisioner.unprovisioned_devices) > 0:
		print("invite time")
		d = network.provisioner.unprovisioned_devices[0]
		pb_adv.Link.set_link(d, network.bearers[0])
		network.provisioner.provision(d.device_uuid)
		input()
	time.sleep(1)
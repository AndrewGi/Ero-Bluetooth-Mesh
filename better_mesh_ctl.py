import time

import network
from bearers import bleson_bearer
print("starting")

network = network.Network()
network.add_bearer(bleson_bearer.BlesonBearer())
while True:
	print(network.provisioner.unprovisioned_devices)
	time.sleep(1)
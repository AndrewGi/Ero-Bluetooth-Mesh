import json
from uuid import UUID
import sys

if __name__ == "__main__":
	print("loading mesh...")
	from bt_mesh import mesh, prov, beacon, network, stack, crypto

	print("loading config")
	from bt_mesh.config import config_client

	print("loading bearer")
	from bt_mesh.bearers.pb_adv import AdvBearer, Link, Links
	from bt_mesh.bearer import Bearer

	print("importing done")
else:
	from applications.bluetooth_mesh.bt_mesh import mesh, prov, beacon, network, stack, crypto
	from applications.bluetooth_mesh.bt_mesh.bearers.pb_adv import AdvBearer, Link, Links, Bearer
	from applications.bluetooth_mesh.bt_mesh.config import config_client
	from applications.bluetooth_mesh.bt_mesh.bearer import Bearer
from typing import *
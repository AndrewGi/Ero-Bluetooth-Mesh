import time
"""
	WARNING: Ero-Bluetooth-Mesh is very unfinished and in a brokenstate!
	It is in ACTIVE DEVELOPMENT
	

"""
from bt_mesh import stack, network, crypto, mesh
from bt_mesh.bearers import bleson_bearer, pb_adv
print("starting")

global_context = crypto.GlobalContext.new()
local_context = crypto.LocalContext.new_provisioner()
network = network.Network(global_context, dict(), mesh.UnicastAddress(1))
stack = stack.Stack(bleson_bearer.BlesonBearer(), global_context, local_context)
print("initialized")

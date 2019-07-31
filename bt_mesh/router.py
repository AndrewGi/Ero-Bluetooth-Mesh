from applications.bluetooth_mesh.ero_bluetooth_mesh import bluetooth_mesh_app
from applications.bluetooth_mesh import bt_mesh


class Router(bt_mesh.Device):
	def __init__(self, device: Device):
		super().__init__(**device.as_dict())
		self.connection_uuid = uuid.uuid4()
		self.last_pong_latency_us = -1 # type: int
		if self.network_id not in bluetooth_mesh_app.routers:
			bluetooth_mesh_app.routers[self.network_id] = set()
		bluetooth_mesh_app.routers[self.network_id].add(self)

	@classmethod
	def new_unregistered(cls, router_uuid: uuid.UUID):
		device = copy.copy(UnregisteredDevice)
		device.device_uuid = router_uuid
		device.type = "unregistered_router"
		return cls(device)

	def create_event(self, event_name: str, event_data: Optional[EventData] = None):
		return bluetooth_mesh_app.create_event(self, event_name, event_data)

	def loggined_in(self) -> bool:
		return self.network_id != 0

	def fire_event(self, event: Event):
		bluetooth_mesh_app.fire_event(event)

	def remove_router(self):
		bluetooth_mesh_app.routers[self.network_id].remove(self)

	@staticmethod
	def receive_message(happened_time: datetime.datetime,  message: Message):
		bluetooth_mesh_app.process_incoming(happened_time, message)

	def send_message(self, message: Message):
		raise NotImplementedError("send_message should be overrided by super class")

	def ping(self):
		self.send_ping()

	def send_ping(self):
		raise NotImplementedError()

	def get_ping_latency_us(self) -> int:
		raise self.last_pong_latency_us

	def send_provision_info(self):
		raise NotImplementedError()

	def report_pong(self, pong_latency_us: int):
		assert pong_latency_us > 0
		self.last_pong_latency_us = pong_latency_us
		self.fire_event(self.create_event("router_pong", {"latency_us": pong_latency_us}))

	def provision(self, network_id: NetworkID, added_by_user: UserID):
		assert self.network_id == 0 and self.device_id == 0, "device could already be provisioned"
		assert self.device_type.startswith("unregistered"), "device type already registered"
		self.remove_router()
		self.network_id = network_id
		new_device = Network.from_network_id(network_id).provision_device(self.device_uuid, network_id, added_by_user)
		#update device fields
		for key in Device.__slots__:
			setattr(self, key, getattr(new_device, key))
		self.send_provision_info()

	def disconnected(self):
		assert self.loggined_in()
		self.fire_event(self.create_event("router_disconnected"))

	def connected(self):
		assert self.loggined_in()
		self.fire_event(self.create_event("router_connected"))

	def finish_provision(self):
		assert self.loggined_in()
		self.fire_event(self.create_event("router_provisioned"))

	def server_pinged(self):
		if self.loggined_in():
			self.fire_event(self.create_event("router_pinged_server"))


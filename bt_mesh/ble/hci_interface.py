from . import hci, adapter, hci_config_parameters

class Interface:
	def open(self) -> None:
		raise NotImplementedError()

	def close(self) -> None:
		raise NotImplementedError()

	def is_open(self) -> bool:
		raise NotImplementedError()

	def write(self, b: bytes) -> None:
		raise NotImplementedError()

	def execute_command(self, command: hci.Command):
		raise NotImplementedError()

	def handle_hci_event(self, event: hci.Event) -> None:
		if event == hci.

	def advertise_enable(self, is_enabled: bool) -> None:
		self.execute_command(hci_config_parameters.AdvertisingEnable(is_enabled).as_command())

	def reset(self) -> None:
		self.execute_command(hci_config_parameters.)


class HCIAdapter(adapter.Adapter):
	def reset(self):
		self
import subprocess
import ssl
import socket
from typing import Optional
from . import hci

def _start_hci_scan():
	return subprocess.Popen(["hcitool", "lescan", "--duplicates"], stdout=subprocess.PIPE)

def _dump_process():
	return subprocess.Popen(["hcidump", "--raw"], stdout=subprocess.PIPE)

def hcitool_cmd(cmd: hci.HCICommand):
	subprocess.Popen(["hcitool", "cmd", str(cmd)])

def read_hci_packet(pipe: subprocess.PIPE) -> bytes:
	def grab_bytes(line: bytes) -> bytes:
		hexs = [int(b, base=16) for b in (line[2:].decode().rstrip().split(" "))]
		return bytes(hexs)
	for l in pipe:
		if l[0]==ord('>'):
			out = grab_bytes(l)
			for l in pipe:
				if l[0] != ord(' '):
					break
				out += grab_bytes(l)
			yield out

def filter_only_mesh(b: bytes) -> Optional[bytes]:
	if len(b) < 16:
		return None
	advertising_type = int(b[15])
	if advertising_type==0x2A:
		return b[16:15+int(b[14])]
	return None



def start():
	print("start hci scan")
	with _start_hci_scan() as _hci_scan:
		print("starting dumper")
		with _dump_process() as dumper:
			for packet in read_hci_packet(dumper.stdout):
				out = filter_only_mesh(packet)
				if out:
					print(out.hex())

if __name__=="__main__":
	start()
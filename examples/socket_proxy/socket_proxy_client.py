from ...bt_mesh.proxys import socket as socket_proxy
from ...bt_mesh.bearers import bleson_bearer
import ssl

CA_CERT_PATH = ""
CLIENT_CERT_PATH = ""
CLIENT_KEY_PATH = ""
HOSTNAME = ""
PORT = 0


def main():
	print("starting...")
	bearer = bleson_bearer.BlesonBearer()
	context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
	context.load_verify_locations(CA_CERT_PATH)
	context.load_cert_chain(certfile=CA_CERT_PATH, keyfile=CLIENT_KEY_PATH)
	print(f"connecting to {HOSTNAME}:{PORT}...")
	pipe = socket_proxy.connect_pipe(HOSTNAME, PORT, context)
	print("connected!")
	proxy = socket_proxy.SocketProxyServer(pipe, bearer)
	input("press enter to close...")


if __name__ == "__main__":
	main()

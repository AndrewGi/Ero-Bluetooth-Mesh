import enum
import os
import struct
from .mesh import *
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, CipherContext
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidTag

Salt = NewType("Salt", bytes)
ProvisioningSalt = NewType("ProvisioningSalt", Salt)
MAC = NewType("MAC", bytes)
NetworkID = NewType("NetworkID", int)


def data_and_mic_bytes(v: Tuple[bytes, MIC]) -> bytes:
	return v[0] + v[1].bytes_be


class InvalidMIC(Exception):
	pass


class NonceType(enum.IntEnum):
	NETWORK = 0
	APPLICATION = 1
	DEVICE = 2
	PROXY = 3
	RFU = 4


class Nonce:
	__slots__ = 'nonce_type',

	def __init__(self, nonce_type: NonceType):
		self.nonce_type = nonce_type

	def as_be_bytes(self) -> bytes:
		raise NotImplementedError()


class NetworkNonce(Nonce):
	STRUCT = struct.Struct("!BB3sHxxL")
	__slots__ = 'ttl', 'ctl', 'seq', 'src', 'iv_index'

	def __init__(self, ttl: TTL, ctl: bool, seq: SEQ, src: Address, iv_index: IVIndex):
		super().__init__(NonceType.NETWORK)
		self.ttl = ttl
		self.ctl = ctl
		self.seq = seq
		self.src = src
		self.iv_index = iv_index

	def as_be_bytes(self) -> bytes:
		ctl_ttl = (self.ctl << 7) | self.ttl
		return self.STRUCT.pack(self.nonce_type, ctl_ttl, seq_bytes(self.seq), self.src, self.iv_index.index)


class ApplicationNonce(Nonce):
	STRUCT = struct.Struct("!BB3sHHL")
	__slots__ = 'aszmic', 'seq', 'src', 'dst', 'iv_index'

	def __init__(self, aszmic: bool, seq: SEQ, src: Address, dst: Address, iv_index: IVIndex):
		super().__init__(NonceType.APPLICATION)
		self.aszmic = aszmic
		self.seq = seq
		self.src = src
		self.dst = dst
		self.iv_index = iv_index

	def as_be_bytes(self) -> bytes:
		return self.STRUCT.pack(self.nonce_type, self.aszmic << 7, seq_bytes(self.seq), self.src, self.dst,
								self.iv_index.index)


class DeviceNonce(Nonce):
	STRUCT = struct.Struct("!BB3sHHL")
	__slots__ = 'aszmic', 'seq', 'src', 'dst', 'iv_index'

	def __init__(self, aszmic: bool, seq: SEQ, src: Address, dst: Address, iv_index: IVIndex):
		super().__init__(NonceType.DEVICE)
		self.aszmic = aszmic
		self.seq = seq
		self.src = src
		self.dst = dst
		self.iv_index = iv_index

	def as_be_bytes(self) -> bytes:
		return self.STRUCT.pack(self.nonce_type, self.aszmic << 7, seq_bytes(self.seq), self.src, self.dst,
								self.iv_index)


class ProxyNonce(Nonce):
	STRUCT = struct.Struct("!Bx3sHxxL")
	__slots__ = 'seq', 'src', 'iv_index'

	def __init__(self, seq: SEQ, src: Address, iv_index):
		super().__init__(NonceType.PROXY)
		self.seq = seq
		self.src = src
		self.iv_index = iv_index

	def as_be_bytes(self) -> bytes:
		return self.STRUCT.pack(self.nonce_type, seq_bytes(self.seq), self.src, self.iv_index)


class Key:
	KEY_LEN = 16
	__slots__ = 'key_bytes',

	def __init__(self, key_bytes: bytes):
		if len(key_bytes) != self.KEY_LEN:
			raise ValueError(f"key len ({len(key_bytes)} not {self.KEY_LEN} bytes long")
		self.key_bytes = key_bytes

	@classmethod
	def from_int(cls, i: int):
		return cls(i.to_bytes(cls.KEY_LEN, byteorder="big"))

	def __str__(self) -> str:
		return self.key_bytes.hex()

	def __repr__(self) -> str:
		return self.__str__()

	def __eq__(self, other: 'Key') -> bool:
		return self.key_bytes == other.key_bytes

	@classmethod
	def _random_key(cls) -> 'Key':
		return cls(os.urandom(cls.KEY_LEN))


class Appkey(Key):
	@classmethod
	def random(cls) -> 'Appkey':
		return cast(cls, cls.random())


class EncryptionKey(Key):
	pass


class PrivacyKey(Key):
	pass


class NetworkKey(Key):
	@classmethod
	def random(cls) -> 'NetworkKey':
		return cast(cls, cls.random())

	def nid_encryption_privacy(self) -> Tuple[NID, EncryptionKey, PrivacyKey]:
		return k2(self, bytes([0x00]))

	def security_material(self) -> 'NetworkSecurityMaterial':
		nid, encryption, privacy = self.nid_encryption_privacy()
		return NetworkSecurityMaterial(self.network_id(), nid, self, encryption, privacy)

	def network_id(self) -> NetworkID:
		return NetworkID(k3(self))


class DeviceKey(Key):
	@classmethod
	def from_salt_and_secret(cls, salt: ProvisioningSalt, secret: 'ECDHSharedSecret') -> 'DeviceKey':
		return cls(k1(salt, secret, b"prdk"))


class ECCKeyPoint:
	__slots__ = "x", "y",

	def __init__(self, x: int, y: int):
		self.x = x
		self.y = y


ec_curve = ec.SECP256R1()


class ECCPublicKey:
	__slots__ = "public_key"

	def __init__(self, public_key: ec.EllipticCurvePublicKey):
		if public_key.curve != ec_curve:
			raise ValueError("public key not NIST-256 key")
		self.public_key = public_key

	@property
	def point(self) -> ECCKeyPoint:
		if self.public_key.curve != ec_curve:
			raise ValueError("public key not NIST-256 key")
		nums = self.public_key.public_numbers()  # type: ec.EllipticCurvePublicNumbers
		return ECCKeyPoint(x=nums.x, y=nums.y)

	@classmethod
	def from_point(cls, point: ECCKeyPoint) -> 'ECCPublicKey':
		return cls(ec.EllipticCurvePublicNumbers(point.x, point.y, ec_curve).public_key(default_backend()))


class ECDHSharedSecret(Key):
	def __init__(self, secret_bytes: bytes):
		super().__init__(secret_bytes)


class ECCPrivateKey:
	__slots__ = "private_key",

	def __init__(self, private_key: ec.EllipticCurvePrivateKey):
		self.private_key = private_key

	def public_key(self) -> ECCPublicKey:
		return ECCPublicKey(self.private_key.public_key())

	@classmethod
	def generate(cls) -> 'ECCPrivateKey':
		return cls(ec.generate_private_key(ec_curve, default_backend()))

	def make_shared_secret(self, peer_public: ECCPublicKey) -> ECDHSharedSecret:
		return ECDHSharedSecret(self.private_key.exchange(ec.ECDH(), peer_public.public_key))


def aes_cmac(key: Key, data: bytes) -> MAC:
	c = cmac.CMAC(algorithms.AES(key.key_bytes), backend=default_backend())
	c.update(data)
	return MAC(c.finalize())


def aes_ccm_encrypt(key: Key, nonce: Nonce, data: bytes, mic_len=32, associated_data: Optional[bytes] = None) -> Tuple[
	bytes, MIC]:
	tag_len = mic_len // 8
	aes_ccm = AESCCM(key.key_bytes, tag_len)
	raw = aes_ccm.encrypt(nonce, data, associated_data)
	mic = MIC(raw[-tag_len:])
	return raw[:-tag_len], mic


def aes_ccm_decrypt(key: Key, nonce: Nonce, data: bytes, mic: MIC, associated_data: Optional[bytes] = None) -> bytes:
	tag_len = len(mic.bytes_be)
	aes_ccm = AESCCM(key.key_bytes, tag_len)
	try:
		return aes_ccm.decrypt(nonce.as_be_bytes(), data + mic.bytes_be, associated_data)
	except InvalidTag:
		raise InvalidMIC()


class SecurityMaterial:
	pass


class TransportSecurityMaterial(SecurityMaterial):
	__slots__ = "key"

	def __init__(self, key: crypto.Key):
		self.key = key

	def aes_ccm_encrypt(self, nonce: Nonce, data: bytes, mic_len: Optional[int] = 32,
						associated_data: Optional[bytes] = None) -> \
			Tuple[bytes, MIC]:
		return aes_ccm_encrypt(self.key, nonce, data, mic_len, associated_data)

	def aes_ccm_decrypt(self, nonce: Nonce, data: bytes, mic: MIC, associated_data: Optional[bytes] = None) -> bytes:
		return aes_ccm_decrypt(self.key, nonce, data, mic, associated_data)

	def transport_encrypt(self, nonce: Nonce, data: bytes, big_mic: Optional[bool] = False,
						  virtual_address: Optional[VirtualAddress] = None) -> Tuple[bytes, MIC]:
		return self.aes_ccm_encrypt(nonce, data, 64 if big_mic else 32,
									virtual_address.uuid.bytes if virtual_address else None)

	def transport_decrypt(self, nonce: Nonce, data: bytes, mic: MIC,
						  virtual_address: Optional[VirtualAddress] = None) -> bytes:
		return self.aes_ccm_decrypt(nonce, data, mic, virtual_address.uuid.bytes if virtual_address else None)


class AppSecurityMaterial(TransportSecurityMaterial):
	def __init__(self, key: Appkey, aid: AID):
		super().__init__(key)
		self.aid = aid

	@classmethod
	def from_key(cls, key: Appkey):
		return cls(key, AID(k4(key.key_bytes)))


class DeviceSecurityMaterial(TransportSecurityMaterial):
	def __init__(self, key: DeviceKey):
		super().__init__(key)

	def transport_encrypt(self, nonce: DeviceNonce, data: bytes, big_mic: Optional[bool] = False, _va: None = None) -> \
			Tuple[bytes, MIC]:
		if _va:
			raise ValueError("device security material doesn't take a virtual address")
		return self.aes_ccm_encrypt(nonce, data, 64 if big_mic else 32)

	def transport_decrypt(self, nonce: DeviceNonce, data: bytes, mic: MIC, _va: None = None) -> bytes:
		if _va:
			raise ValueError("device security material doesn't take a virtual address")
		return self.aes_ccm_decrypt(nonce, data, mic)


class NetworkSecurityMaterial(SecurityMaterial):
	__slots__ = "network_id", "nid", "net_key", "encryption_key", "privacy_key"

	def __init__(self, network_id: NetworkID, nid: NID, net_key: NetworkKey, encryption_key: EncryptionKey,
				 privacy_key: PrivacyKey):
		self.network_id = network_id
		self.nid = nid
		self.net_key = net_key
		self.encryption_key = encryption_key
		self.privacy_key = privacy_key


def aes_ecb_encrypt(key: Key, clear_text: bytes) -> bytes:
	encryptor = Cipher(algorithms.AES(key=key.key_bytes), ECB(), default_backend()).encryptor()  # type: CipherContext
	encryptor.update(clear_text)
	return encryptor.finalize()


def aes_ecb_decrypt(key: Key, cipher_text: bytes) -> bytes:
	decryptor = Cipher(algorithms.AES(key=key.key_bytes), ECB(), default_backend()).decryptor()  # type: CipherContext
	decryptor.update(cipher_text)
	return decryptor.finalize()


def s1(m: Union[bytes, str]) -> Salt:
	assert m, "m can not be empty"
	if isinstance(m, str):
		m = m.encode()
	return Salt(aes_cmac(Key(b'\x00' * Key.KEY_LEN), m))


def k1(salt: Salt, key: Key, info: bytes) -> MAC:
	first_pass = Key(aes_cmac(Key(salt), key.key_bytes))
	return aes_cmac(first_pass, info)


def k2(n: Key, p: bytes) -> Tuple[NID, EncryptionKey, PrivacyKey]:
	salt = s1("smk2")
	t = aes_cmac(Key(salt), n.key_bytes)
	t1 = aes_cmac(Key(t), p + b'\x01')
	t2 = aes_cmac(Key(t), t1 + p + b'\x02')
	t3 = aes_cmac(Key(t), t2 + p + b'\x03')
	nid = NID(t1[15] & 0x7f)
	return nid, EncryptionKey(t2), PrivacyKey(t3)


def k3(n: bytes) -> int:
	if len(n) != 16:
		ValueError(f"n should be 16 bytes long not {len(n)}")
	salt = s1("smk3")
	t = aes_cmac(Key(salt), n)
	return int.from_bytes(aes_cmac(Key(t), b'id64\x01')[8:16], byteorder="big")


def k4(n: bytes) -> int:
	if len(n) != 16:
		ValueError(f"n should be 16 bytes long not {len(n)}")
	salt = s1("smk4")
	t = aes_cmac(Key(salt), n)
	return aes_cmac(Key(t), b'id6\x01')[15] & 63


def id128(n: Key, s: str) -> bytes:
	salt = s1(s)
	return k1(salt, n, b"id128\x01")


class NetworkAppKeys:

	def __init__(self, net_sm: NetworkSecurityMaterial):
		self.net_sm = net_sm
		self.app_sms: List[AppSecurityMaterial] = list()

	def get_aid(self, aid: AID) -> Generator[AppSecurityMaterial, None, None]:
		for app_sm in self.app_sms:
			if app_sm.aid == aid:
				yield app_sm

	def add_app_security_material(self, app_sm: AppSecurityMaterial):
		self.app_sms.append(app_sm)

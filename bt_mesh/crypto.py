import enum
import struct
from .mesh import *
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
Salt = NewType("Salt", bytes)
MAC = NewType("MAC", bytes)


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
		return self.STRUCT.pack(self.nonce_type, ctl_ttl, seq_bytes(self.seq), self.src, self.iv_index)


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
								self.iv_index)





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


class Appkey(Key):
	pass


class NetworkKey(Key):
	pass


class EncryptionKey(Key):
	pass


class PrivacyKey(Key):
	pass


class DeviceKey(Key):
	pass


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

	def point(self) -> ECCKeyPoint:
		if self.public_key.curve != ec_curve:
			raise ValueError("public key not NIST-256 key")
		nums = self.public_key.public_numbers() # type: ec.EllipticCurvePublicNumbers
		return ECCKeyPoint(x=nums.x, y=nums.y)

	def verify(self, signature: bytes, data: bytes):
		return self.public_key.verify(signature, data)


class ECCPrivateKey:
	__slots__ = "private_key",
	def __init__(self, private_key: ec.EllipticCurvePrivateKey):
		self.private_key = private_key

	def public_key(self) -> ECCPublicKey:
		return ECCPublicKey(self.private_key.public_key())






def aes_cmac(key: Key, data: bytes) -> MAC:
	return MAC(CMAC.new(key.key_bytes, data, ciphermod=AES, mac_len=16).digest())


def aes_ccm_encrypt(key: Key, nonce: Nonce, data: bytes, mic_len=32) -> Tuple[bytes, MIC]:
	if data is None:
		data = bytes()
	aes = AES.new(key=key.key_bytes, mode=AES.MODE_CCM, nonce=nonce.as_be_bytes(), mac_len=mic_len)
	encrypted_data, digest = aes.encrypt_and_digest(data)
	return encrypted_data, MIC(digest)

def aes_ccm_decrypt(key: Key, nonce: Nonce, data: bytes, mic_len=32):
	pass


def be_encrypt(key: Key, clear_text: bytes) -> bytes:
	aes = AES.new(key=key.key_bytes, mode=AES.MODE_ECB)
	return aes.encrypt(clear_text)


def s1(m: str) -> Salt:
	assert m, "m can not be empty"
	return Salt(aes_cmac(Key(b'\x00' * Key.KEY_LEN), m.encode()))


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
	return k1(salt, n, "id128\x01")

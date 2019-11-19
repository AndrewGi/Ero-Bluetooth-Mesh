import enum
import os
import struct
from abc import ABC
from .mesh import *
from .serialize import Serializable
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, CipherContext
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import exceptions

Salt = NewType("Salt", bytes)
ProvisioningSalt = NewType("ProvisioningSalt", Salt)
MAC = NewType("MAC", bytes)


def data_and_mic_bytes(b: bytes, m: MIC) -> bytes:
	return b + m.bytes_be


class InvalidMIC(Exception):
	pass


class InvalidKey(Exception):
	pass


class NonceType(enum.IntEnum):
	NETWORK = 0
	APPLICATION = 1
	DEVICE = 2
	PROXY = 3
	RFU = 4


class Nonce:
	__slots__ = 'nonce_type',

	def __init__(self, nonce_type: Optional[NonceType]):
		self.nonce_type = nonce_type

	def as_be_bytes(self) -> bytes:
		raise NotImplementedError()


class NetworkNonce(Nonce):
	STRUCT = struct.Struct("!BB3sHxxL")
	__slots__ = 'ttl', 'ctl', 'seq', 'src', 'iv_index'

	def __init__(self, ttl: TTL, ctl: bool, seq: Seq, src: Address, iv_index: IVIndex):
		super().__init__(NonceType.NETWORK)
		self.ttl = ttl
		self.ctl = ctl
		self.seq = seq
		self.src = src
		self.iv_index = iv_index

	def as_be_bytes(self) -> bytes:
		ctl_ttl = (self.ctl << 7) | self.ttl.value
		return self.STRUCT.pack(self.nonce_type, ctl_ttl, self.seq.to_bytes(), self.src, self.iv_index)


class ApplicationNonce(Nonce):
	STRUCT = struct.Struct("!BB3sHHL")
	__slots__ = 'aszmic', 'seq', 'src', 'dst', 'iv_index'

	def __init__(self, aszmic: bool, seq: Seq, src: Address, dst: Address, iv_index: IVIndex):
		super().__init__(NonceType.APPLICATION)
		self.aszmic = aszmic
		self.seq = seq
		self.src = src
		self.dst = dst
		self.iv_index = iv_index

	def as_be_bytes(self) -> bytes:
		return self.STRUCT.pack(self.nonce_type, self.aszmic << 7, self.seq.to_bytes(), self.src, self.dst,
								self.iv_index)


class DeviceNonce(Nonce):
	STRUCT = struct.Struct("!BB3sHHL")
	__slots__ = 'aszmic', 'seq', 'src', 'dst', 'iv_index'

	def __init__(self, aszmic: bool, seq: Seq, src: Address, dst: Address, iv_index: IVIndex):
		super().__init__(NonceType.DEVICE)
		self.aszmic = aszmic
		self.seq = seq
		self.src = src
		self.dst = dst
		self.iv_index = iv_index

	def as_be_bytes(self) -> bytes:
		return self.STRUCT.pack(self.nonce_type, self.aszmic << 7, self.seq.to_bytes(), self.src, self.dst,
								self.iv_index)


class ProxyNonce(Nonce):
	STRUCT = struct.Struct("!Bx3sHxxL")
	__slots__ = 'seq', 'src', 'iv_index'

	def __init__(self, seq: Seq, src: Address, iv_index):
		super().__init__(NonceType.PROXY)
		self.seq = seq
		self.src = src
		self.iv_index = iv_index

	def as_be_bytes(self) -> bytes:
		return self.STRUCT.pack(self.nonce_type, self.seq.to_bytes(), self.src, self.iv_index)


class Key(ByteSerializable):
	KEY_LEN: int = 16
	__slots__ = 'key_bytes',

	def __init__(self, key_bytes: bytes):
		if len(key_bytes) != self.KEY_LEN:
			raise ValueError(f"key len ({len(key_bytes)} not {self.KEY_LEN} bytes long")
		self.key_bytes = key_bytes

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Key':
		return cls(b)

	@classmethod
	def from_int(cls, i: int):
		return cls(i.to_bytes(cls.KEY_LEN, byteorder="big"))

	def hex(self) -> str:
		return self.key_bytes.hex()

	@classmethod
	def from_str(cls, s: str) -> 'Key':
		return cls(bytes.fromhex(s))

	def __str__(self) -> str:
		return self.hex()

	def __repr__(self) -> str:
		return self.__str__()

	def __len__(self) -> int:
		return len(self.key_bytes)

	def __eq__(self, other: 'Key') -> bool:
		return self.key_bytes == other.key_bytes

	@classmethod
	def _random_key(cls) -> 'Key':
		return cls(os.urandom(cls.KEY_LEN))

	def to_bytes(self) -> bytes:
		return self.key_bytes


class AppKey(Key):
	@classmethod
	def random(cls) -> 'AppKey':
		return cast(cls, cls.random())


class EncryptionKey(Key):
	pass


class PrivacyKey(Key):
	pass


class IdentityKey(Key):
	pass


class BeaconKey(Key):
	pass


class SessionNonce(Nonce, ABC):
	__slots__ = "nonce",

	def __init__(self, nonce: bytes):
		if len(nonce) != 13:
			raise ValueError(f"nonce should be 13 bytes not {len(nonce)}")
		super().__init__(None)
		self.nonce = nonce

	def to_bytes(self) -> bytes:
		return self.nonce

	def as_be_bytes(self) -> bytes:
		return self.to_bytes()

	@classmethod
	def from_secret(cls, secret: 'ECDHSharedSecret', provisioning_salt: ProvisioningSalt) -> 'SessionNonce':
		return cls(k1(provisioning_salt, secret, b"prsn")[-13:])


class SessionKey(Key):
	@classmethod
	def from_secret(cls, secret: 'ECDHSharedSecret', provisioning_salt: ProvisioningSalt) -> 'SessionKey':
		return cls(k1(provisioning_salt, secret, b"prsk"))


class NetworkKey(Key):
	@classmethod
	def random(cls) -> 'NetworkKey':
		return cast(cls, cls._random_key())

	def nid_encryption_privacy(self) -> Tuple[NID, EncryptionKey, PrivacyKey]:
		return k2(self, b'\x00')

	def security_material(self) -> 'NetworkSecurityMaterial':
		nid, encryption, privacy = self.nid_encryption_privacy()
		return NetworkSecurityMaterial(self.network_id(), nid, self, encryption, privacy, self.identity_key(),
									   self.beacon_key())

	def network_id(self) -> NetworkID:
		return NetworkID(k3(self))

	def identity_key(self) -> IdentityKey:
		salt = s1("nkik")
		p = b"id128\x01"
		return IdentityKey(k1(salt, self, p))

	def beacon_key(self) -> BeaconKey:
		salt = s1("nkbk")
		p = b"id128\x01"
		return BeaconKey(k1(salt, self, p))


class DeviceKey(Key):
	@classmethod
	def from_salt_and_secret(cls, salt: ProvisioningSalt, secret: 'ECDHSharedSecret') -> 'DeviceKey':
		return cls(k1(salt, secret, b"prdk"))


class ECCKeyPoint:
	__slots__ = "x", "y",

	def __init__(self, x: int, y: int):
		assert isinstance(x, int)
		assert isinstance(y, int)
		self.x = x
		self.y = y


ECC_NUM_LEN = 32
ec_curve = ec.SECP256R1()


class ECCPublicKey(ByteSerializable):
	__slots__ = "public_key"

	def __init__(self, public_key: ec.EllipticCurvePublicKeyWithSerialization):
		if public_key.curve.name != ec_curve.name:
			raise ValueError(f"public key not NIST-256 key ({public_key.curve.name})")
		self.public_key = public_key

	@property
	def point(self) -> ECCKeyPoint:
		if self.public_key.curve.name != ec_curve.name:
			raise ValueError("public key not NIST-256 key")
		nums: ec.EllipticCurvePublicNumbers = self.public_key.public_numbers()
		return ECCKeyPoint(x=nums.x, y=nums.y)

	@classmethod
	def from_point(cls, point: ECCKeyPoint) -> 'ECCPublicKey':
		return cls(ec.EllipticCurvePublicNumbers(point.x, point.y, ec_curve).public_key(default_backend()))

	def make_private_key(self, private_value: Union[int, bytes]) -> 'ECCPrivateKey':
		value = private_value if isinstance(private_value, int) else int.from_bytes(private_value, "big")
		return ECCPrivateKey(ec.EllipticCurvePrivateNumbers(value, self.public_key.public_numbers())
							 .private_key(default_backend()))


class ECDHSharedSecret(Key):
	KEY_LEN = 32

	def __init__(self, secret_bytes: bytes):
		super().__init__(secret_bytes)


class ECCPrivateKey:
	__slots__ = "private_key",

	def __init__(self, private_key: ec.EllipticCurvePrivateKeyWithSerialization):
		self.private_key = private_key

	def public_key(self) -> ECCPublicKey:
		return ECCPublicKey(self.private_key.public_key())

	@classmethod
	def generate(cls) -> 'ECCPrivateKey':
		return cls(ec.generate_private_key(ec_curve, default_backend()))

	def make_shared_secret(self, peer_public: ECCPublicKey) -> ECDHSharedSecret:
		assert isinstance(peer_public, ECCPublicKey)
		return ECDHSharedSecret(self.private_key.exchange(ec.ECDH(), peer_public.public_key))

	def private_value(self) -> int:
		return cast(ec.EllipticCurvePrivateNumbers, self.private_key.private_numbers()).private_value

	def to_bytes(self) -> bytes:
		"""
		:return: returns private key value as big endian bytes
		"""
		return self.private_value().to_bytes(ECC_NUM_LEN, "big")


def aes_cmac(key: Key, data: bytes) -> MAC:
	c = cmac.CMAC(algorithms.AES(key.key_bytes), backend=default_backend())
	c.update(data)
	return MAC(c.finalize())


def aes_ccm_encrypt(key: Key, nonce: Nonce, data: bytes, mic_len=32, associated_data: Optional[bytes] = None) -> Tuple[
	bytes, MIC]:
	tag_len = mic_len // 8
	aes_ccm = AESCCM(key.key_bytes, tag_len)
	raw = aes_ccm.encrypt(nonce.as_be_bytes(), data, associated_data)
	mic = MIC(raw[-tag_len:])
	return raw[:-tag_len], mic


def aes_ccm_decrypt(key: Key, nonce: Nonce, data: bytes, mic: MIC, associated_data: Optional[bytes] = None) -> bytes:
	tag_len = len(mic.bytes_be)
	aes_ccm = AESCCM(key.key_bytes, tag_len)
	try:
		return aes_ccm.decrypt(nonce.as_be_bytes(), data + mic.bytes_be, associated_data)
	except exceptions.InvalidKey:
		raise InvalidKey()
	except exceptions.InvalidTag:
		raise InvalidMIC()


class SecurityMaterial(ABC):
	__slots__ = "key"

	def __init__(self, key: Key):
		self.key = key


class TransportSecurityMaterial(SecurityMaterial, ABC):

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
	def __init__(self, key: AppKey, aid: AID):
		super().__init__(key)
		self.aid = aid

	@classmethod
	def from_key(cls, key: AppKey):
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
	__slots__ = "network_id", "nid", "encryption_key", "privacy_key", "identity_key", "beacon_key"

	def __init__(self, network_id: NetworkID, nid: NID, net_key: NetworkKey, encryption_key: EncryptionKey,
				 privacy_key: PrivacyKey, identity_key: IdentityKey, beacon_key: BeaconKey):
		super().__init__(net_key)
		self.network_id = network_id
		self.nid = nid
		self.key = net_key
		self.encryption_key = encryption_key
		self.privacy_key = privacy_key
		self.identity_key = identity_key
		self.beacon_key = beacon_key

	@classmethod
	def from_key(cls, network_key: NetworkKey) -> 'NetworkSecurityMaterial':
		return network_key.security_material()


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


def k3(n: Key) -> int:
	if len(n) != 16:
		ValueError(f"n should be 16 bytes long not {len(n)}")
	salt = s1("smk3")
	t = aes_cmac(Key(salt), n.key_bytes)
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


class KeyRefreshPhase(enum.IntEnum):
	Normal = 0x00  # Normal operation
	Phase1 = 0x01  # Key distribution
	Phase2 = 0x02  # Use new keys
	Phase3 = 0x03  # Revoke old keys


class KeyIndexSlot(Serializable, ABC):
	__slots__ = "index", "new", "old", "phase"

	def __init__(self, index: KeyIndex, old: SecurityMaterial, new: Optional[SecurityMaterial] = None,
				 phase: Optional[KeyRefreshPhase] = KeyRefreshPhase.Normal):
		self.index = index
		self.new = new
		self.old = old
		self.phase = phase

	def tx_sm(self) -> SecurityMaterial:
		if self.phase == KeyRefreshPhase.Phase2:
			return self.new
		else:
			return self.old

	def rx_sms(self) -> Tuple[SecurityMaterial, Optional[SecurityMaterial]]:
		if self.phase == KeyRefreshPhase.Normal:
			return self.old, None
		elif self.phase == KeyRefreshPhase.Phase1:
			return self.old, self.new
		elif self.phase == KeyRefreshPhase.Phase2:
			return self.old, self.new
		raise NotImplementedError("unhandled key phases")

	def revoke(self):
		if self.phase != KeyRefreshPhase.Phase2:
			raise RuntimeError(f"can only revoke from phase 2 not {self.phase}")
		self.old = self.new
		self.new = None
		self.phase = KeyRefreshPhase.Normal

	def to_dict(self) -> Dict[str, Any]:
		return {
			"index": self.index.value,
			"phase": self.phase.value,
			"new_key": self.new.key.hex() if self.new else None,
			"old_key": self.old.key.hex()
		}


class AppKeyIndexSlot(KeyIndexSlot):
	def __init__(self, index: AppKeyIndex, old: AppSecurityMaterial, new: Optional[AppSecurityMaterial] = None,
				 phase: Optional[KeyRefreshPhase] = KeyRefreshPhase.Normal):
		super().__init__(index, old, new, phase)

	def tx_sm(self) -> AppSecurityMaterial:
		return cast(AppSecurityMaterial, super().tx_sm())

	def rx_sms(self) -> Tuple[AppSecurityMaterial, Optional[AppSecurityMaterial]]:
		return cast(Tuple[AppSecurityMaterial, Optional[AppSecurityMaterial]], super().rx_sms())

	def rx_by_aid(self, aid: AID) -> Generator[AppSecurityMaterial, None, None]:
		old, new = self.rx_sms()
		if old.aid == aid:
			yield old
		if new and new.aid == aid:
			yield new

	@classmethod
	def from_dict(cls, d: Dict[str, Any]) -> 'AppKeyIndexSlot':
		new = None if d["new"] is None else AppSecurityMaterial.from_key(AppKey.from_str(d["new"]))

		return cls(index=AppKeyIndex(d["index"]), phase=KeyRefreshPhase(d["phase"]),
				   new=new, old=AppSecurityMaterial.from_key(AppKey.from_str(d["old"])))


class NetKeyIndexSlot(KeyIndexSlot):
	def __init__(self, index: NetKeyIndex, old: NetworkSecurityMaterial, new: Optional[NetworkSecurityMaterial] = None,
				 phase: Optional[KeyRefreshPhase] = KeyRefreshPhase.Normal):
		super().__init__(index, old, new, phase)

	@classmethod
	def new_primary(cls) -> 'NetKeyIndexSlot':
		return cls(NetKeyIndex(0x0000), NetworkKey.random().security_material())

	def tx_sm(self) -> NetworkSecurityMaterial:
		return cast(NetworkSecurityMaterial, super().tx_sm())

	def rx_sms(self) -> Tuple[NetKeyIndex, NetworkSecurityMaterial, Optional[NetworkSecurityMaterial]]:
		netkey = cast(NetKeyIndex, self.index)
		sms = cast(Tuple[NetworkSecurityMaterial, Optional[NetworkSecurityMaterial]], super().rx_sms())
		return netkey, sms[0], sms[1]

	def rx_by_nid(self, nid: NID) -> Generator[NetworkSecurityMaterial, None, None]:
		_index, old, new = self.rx_sms()
		if old.nid == nid:
			yield old
		if new and new.nid == nid:
			yield new

	@classmethod
	def from_dict(cls, d: Dict[str, Any]) -> 'NetKeyIndexSlot':
		new = None if d["new_key"] is None else NetworkSecurityMaterial.from_key(NetworkKey.from_str(d["new_key"]))

		return cls(index=NetKeyIndex(d["index"]), phase=KeyRefreshPhase(d["phase"]),
				   new=new, old=NetworkSecurityMaterial.from_key(NetworkKey.from_str(d["old_key"])))


class GlobalContext(Serializable):
	__slots__ = "apps", "nets", "iv_index", "iv_updating"

	def __init__(self, iv_index: IVIndex, primary_net: NetKeyIndexSlot, iv_updating: bool = False):
		if primary_net.index != 0:
			raise ValueError(f"primary net key has to have index 0x0000 not 0x{primary_net.index:04X}")
		self.iv_index = iv_index
		self.iv_updating = iv_updating
		self.apps: Dict[AppKeyIndex, AppKeyIndexSlot] = dict()
		self.nets: Dict[NetKeyIndex, NetKeyIndexSlot] = dict()
		self.net_id_to_index: Dict[NetworkID, NetKeyIndex] = dict()
		self.nets[NetKeyIndex()] = primary_net

	@classmethod
	def new(cls) -> 'GlobalContext':
		return cls(IVIndex(), NetKeyIndexSlot.new_primary())

	def get_iv_index(self, ivi: Optional[bool] = None) -> Optional[IVIndex]:
		if not ivi:
			return self.iv_index
		elif self.iv_index.ivi() == ivi:
			return self.iv_index
		elif self.iv_updating:
			if self.iv_index == IVIndex(0):
				return None
			else:
				return self.iv_index.prev_iv()
		else:
			return None  # ivi doesn't match and not updating

	def primary_net(self):
		return self.nets[NetKeyIndex(0)]

	def add_app(self, slot: AppKeyIndexSlot):
		if slot.index in self.apps:
			raise ValueError(f"app key index {slot.index} already exists")
		self.apps[cast(AppKeyIndex, slot.index)] = slot

	def add_net(self, slot: NetKeyIndexSlot):
		if slot.index in self.nets:
			raise ValueError(f"net key index {slot.index} already exists")
		self.nets[cast(NetKeyIndex, slot.index)] = slot
		if slot.new:
			self.net_id_to_index[cast(NetworkSecurityMaterial, slot.new).network_id] = slot.index
		self.net_id_to_index[cast(NetworkSecurityMaterial, slot.old).network_id] = slot.index

	def to_dict(self) -> Dict[str, Any]:
		return {
			"iv_index": self.iv_index.value,
			"iv_updating": self.iv_updating,
			"apps": [d.to_dict() for d in self.apps.values()],
			"nets": [d.to_dict() for d in self.nets.values()]
		}

	@classmethod
	def from_dict(cls, d: Dict[str, Any]) -> 'GlobalContext':
		primary = NetKeyIndexSlot.from_dict(d["nets"][0])
		context = cls(IVIndex(d["iv_index"]), primary)
		for raw_net in d["nets"][1:]:
			net = NetKeyIndexSlot.from_dict(raw_net)
			context.add_net(net)

		for raw_app in d["apps"]:
			app = AppKeyIndexSlot.from_dict(raw_app)
			context.apps[cast(AppKeyIndex, app.index)] = app

		return context

	def get_nid_rx_keys(self, nid: NID) -> Generator[Tuple[NetKeyIndex, NetworkSecurityMaterial], None, None]:
		for slot in self.nets.values():
			for rx_key in slot.rx_by_nid(nid):
				yield slot.index, rx_key

	def get_aid_rx_keys(self, aid: AID) -> Generator[Tuple[AppKeyIndex, AppSecurityMaterial], None, None]:
		for slot in self.apps.values():
			for rx_key in slot.rx_by_aid(aid):
				yield slot.index, rx_key

	def get_app(self, index: AppKeyIndex) -> AppKeyIndexSlot:
		return self.apps[index]

	def get_net(self, index: NetKeyIndex) -> NetKeyIndexSlot:
		return self.nets[index]

	def get_beacon_key(self, network_id: NetworkID) -> Optional[Tuple[NetKeyIndex, BeaconKey]]:
		try:
			net_index = self.net_id_to_index[network_id]
		except KeyError:
			# Unknown network ID
			return None
		else:
			net_slot = self.nets[net_index]
			if net_slot.new:
				net_sm = cast(NetworkSecurityMaterial, net_slot.new)
				if net_sm.network_id == network_id:
					return net_index, net_sm.beacon_key
			net_sm = cast(NetworkSecurityMaterial, net_slot.old)
			if net_sm.network_id == network_id:
				return net_index, net_sm.beacon_key
			# No matches
			return None


class LocalContext(Serializable):
	__slots__ = "seq", "device_sm", "transmit_parameters"

	def __init__(self, seq: Seq, transmit_parameters: TransmitParameters, device_sm: Optional[DeviceSecurityMaterial]):
		self.seq = seq
		self.transmit_parameters = transmit_parameters
		self.device_sm = device_sm

	@classmethod
	def new_provisioner(cls) -> 'LocalContext':
		return cls(Seq(), TransmitParameters(4, 20), None)

	def seq_inc(self) -> Seq:
		return self.seq_allocate(1)

	def seq_allocate(self, amount: int) -> Seq:
		assert amount > 0
		start_seq = self.seq
		self.seq += amount
		return start_seq

	def to_dict(self) -> Dict[str, Any]:
		return {
			"seq": self.seq,
			"transmit_parameters": self.transmit_parameters.to_dict(),
			"device_key": str(self.device_sm.key)
		}

	@classmethod
	def from_dict(cls, d: Dict[str, Any]) -> 'LocalContext':
		seq = Seq(d["seq"])
		transmit_parameters = TransmitParameters.from_dict(d["transmit_parameters"])
		device_key = DeviceKey.from_str(d["device_key"])
		return cls(seq, transmit_parameters, DeviceSecurityMaterial(device_key))

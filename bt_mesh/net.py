from .mesh import *
from . import crypto
import struct


def xor_bytes(b1: bytes, b2: bytes) -> bytes:
	return bytes(a ^ b for a, b in zip(b1, b2))


class NetworkSecurityMaterials:
	__slots__ = "nid", "iv_index", "privacy_key", "encryption_key", "network_nonce"

	def __init__(self, nid: NID, ivi_index: IVIndex, privacy_key: crypto.PrivacyKey,
				 encryption_key: crypto.EncryptionKey):
		self.nid = nid
		self.iv_index = ivi_index
		self.privacy_key = privacy_key
		self.encryption_key = encryption_key

	def ivi(self) -> bool:
		return self.iv_index.ivi()


class PDU:
	__slots__ = ("ivi", "nid", "ctl", "ttl", "seq", "src", "dst", "transport_pdu")

	def __init__(self, ivi: bool, nid: NID, ctl: bool, ttl: TTL, seq: int, src: Address, dst: Address,
				 transport_pdu: bytes):
		self.ivi = ivi
		self.nid = nid
		self.ctl = ctl
		self.ttl = ttl
		self.seq = seq
		self.src = src
		self.dst = dst
		self.transport_pdu = transport_pdu

	def mic_bit_size(self) -> int:
		if self.ctl:
			return 64
		else:
			return 32

	def _bytes_to_encrypt(self) -> bytes:
		return self.dst.to_bytes(2, byteorder="big") + self.transport_pdu

	def encrypt(self, key: crypto.EncryptionKey, iv_index: crypto.IVIndex) -> Tuple[bytes, MIC]:
		self.ivi = iv_index.ivi()
		return crypto.aes_ccm_encrypt(key, self.net_nonce(iv_index), self._bytes_to_encrypt(), mic_len=32)

	def net_nonce(self, iv_index: IVIndex) -> crypto.NetworkNonce:
		return crypto.NetworkNonce(self.ttl, self.ctl, self.seq, self.src, iv_index)

	@staticmethod
	def decrypt(key: crypto.EncryptionKey, nonce: crypto.NetworkNonce, data: bytes, mic: MIC) -> bytes:
		return crypto.aes_ccm_decrypt(key, nonce, data, mic)

	@staticmethod
	def pecb(privacy_key: crypto.PrivacyKey, iv_index: IVIndex, privacy_random: bytes) -> bytes:
		return crypto.aes_ecb_encrypt(privacy_key, struct.pack("!4xL6s", iv_index, privacy_random[0:6]))

	def obfuscate_and_encrypt(self, privacy_key: crypto.PrivacyKey, iv_index: IVIndex) -> \
			Tuple[bytes, bytes]:
		"""

		:param privacy_key:
		:param nonce:
		:param iv_index:
		:return: obfuscated and encrypted (in that order) data
		"""
		encrypted_dst_trans_pdu, net_mic = self.encrypt(privacy_key.key_bytes, iv_index)
		privacy_random = encrypted_dst_trans_pdu + net_mic.bytes_be
		pecb = self.pecb(privacy_key, iv_index, privacy_random)
		return privacy_random, xor_bytes(
			struct.pack("!B3sH", (self.ctl << 7 | self.ttl), seq_bytes(self.seq), self.src), pecb[0:5])

	@classmethod
	def deobfuscate(cls, b: bytes, privacy_key: crypto.PrivacyKey, iv_index: IVIndex) -> Tuple[bool, TTL, Seq, Address]:
		privacy_random = b[8:8 + 7]
		pecb = cls.pecb(privacy_key, iv_index, privacy_random)
		ctl_ttl, seq, src = struct.unpack("!B3sH", xor_bytes(pecb, b[0:8]))
		return (ctl_ttl >> 7) == 1, TTL(ctl_ttl % 0x7F), Seq(int.from_bytes(seq, byteorder="big")), Address(src)

	@staticmethod
	def ivi_nid(b: bytes) -> Tuple[bool, NID]:
		return (b[0] & 0x80 != 0), NID(b[0] & 0x7F)

	@classmethod
	def from_bytes(cls, b: bytes, sec_mat: NetworkSecurityMaterials) -> 'PDU':
		ivi, nid = cls.ivi_nid(b)
		ctl, ttl, seq, src = cls.deobfuscate(b[1:], sec_mat.privacy_key, sec_mat.iv_index)
		net_mic_len = 8 if ctl else 4 # 64 bits if CTL else 32 bits
		net_mic = b[-net_mic_len:]
		encrypted_transport = b[7:-net_mic_len]
		network_nonce = crypto.NetworkNonce(ttl, ctl, seq, src, sec_mat.iv_index)
		dst_transport_pdu = cls.decrypt(sec_mat.encryption_key, network_nonce, encrypted_transport, net_mic_len)
		dst = Address(dst_transport_pdu[:2])
		transport_pdu = dst_transport_pdu[2:]
		return cls(ivi, nid, ctl, ttl, seq, src, dst, transport_pdu)



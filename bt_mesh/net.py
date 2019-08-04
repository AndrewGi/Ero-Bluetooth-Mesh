from .mesh import *
from . import transport, crypto
import struct

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
	return bytes(a ^ b for a, b in zip(b1, b2))

class PDU:

	__slots__ = ("ivi", "nid", "ctl", "ttl", "seq", "src", "dst", "transport_pdu", "net_mic")
	def __init__(self, ivi: bool, nid: NID, ctl: bool, ttl: TTL, seq: int, src: Address, dst: Address,
				 transport_pdu: transport.LowerPDU, net_mic: MIC):
		self.ivi = ivi
		self.nid = nid
		self.ctl = ctl
		self.ttl = ttl
		self.seq = seq
		self.src = src
		self.dst = dst
		self.transport_pdu = transport_pdu
		self.net_mic = net_mic

	def mic_bit_size(self) -> int:
		if self.ctl:
			return 64
		else:
			return 32

	def _bytes_to_encrypt(self) -> bytes:
		return self.dst.to_bytes(2, byteorder="big") + self.transport_pdu.to_bytes()

	def encrypt(self, key: crypto.EncryptionKey, nonce: crypto.NetworkNonce) -> Tuple[bytes, MIC]:
		return crypto.aes_ccm_encrypt(key, nonce, self._bytes_to_encrypt(), mic_len=32)

	@staticmethod
	def pecb(privacy_key: crypto.PrivacyKey, iv_index: IVIndex, privacy_random: bytes) -> bytes:
		return crypto.be_encrypt(privacy_key, struct.pack("!4xL6s", iv_index, privacy_random[0:6]))

	def obfuscate_and_encrypt(self, privacy_key: crypto.PrivacyKey, nonce: crypto.NetworkNonce, iv_index: IVIndex) -> Tuple[bytes, bytes]:
		"""

		:param privacy_key:
		:param subnet_key:
		:param nonce:
		:param iv_index:
		:return: obfuscated and encrypted (in that order) data
		"""
		encrypted_dst_trans_pdu, net_mic = self.encrypt(privacy_key.key_bytes, nonce)
		privacy_random = encrypted_dst_trans_pdu + net_mic.bytes_be
		pecb = self.pecb(privacy_key, iv_index, privacy_random)
		return privacy_random, xor_bytes(struct.pack("!B3sH", (self.ctl << 7 | self.ttl), seq_bytes(self.seq), self.src), pecb[0:5])

	@staticmethod
	def deobfuscate(cls, b: bytes, privacy_key: crypto.PrivacyKey, iv_index: IVIndex) -> Tuple[bool, TTL, SEQ, Address]:
		privacy_random = b[8:8+7]
		pecb = cls.pecb(privacy_key, iv_index, privacy_random)
		ctl_ttl, seq, src = struct.unpack("!B3sH", xor_bytes(pecb, b[0:8]))
		return (ctl_ttl >> 7) == 1, TTL(ctl_ttl%0x7F), SEQ(int.from_bytes(seq, byteorder="big")), Address(src)

	def from_bytes(self, b: bytes) -> 'PDU':
		raise NotImplementedError()

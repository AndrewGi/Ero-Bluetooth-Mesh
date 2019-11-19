from .. import transport
import unittest

class MessageTests(unittest.TestCase):

	def test_message1(self):
		opcode = transport.CTLOpcode.FRIEND_REQ
		
from typing import *
import enum
import abc
from ..serialize import *


class U8le(U8):
	byteorder = "little"


class U8be(U8):
	byteorder = "big"


class U16le(U16):
	byteorder = "little"


class U16be(U16):
	byteorder = "big"


class PacketType(U8le, enum.Enum):
	Command = 1
	AsynchronousData = 2
	SynchronousData = 3
	Event = 4
	ExtendedCommand = 9


class Packet(Serializable, abc.ABC):
	pass


class OGF(enum.IntEnum):
	"""
		OGF: Opcode group field
	"""
	NOP = 0x00
	LinkControl = 0x01
	LinkPolicy = 0x02
	HCIControlBandband = 0x03
	InformationalParameters = 0x04
	StatusParameters = 0x05
	Testing = 0x06
	LEController = 0x08
	VendorSpecific = 0x3F


OGFClasses: Dict[OGF, type] = dict()


class OCF(enum.Enum, abc.ABC):
	"""
		OCF: Opcode command field
	"""


class LinkControlOpcode(OCF):
	Inquiry = 0x0001
	InquiryCancel = 0x0002
	PeriodicInquiryMode = 0x0003
	ExitPeriodicInquiryMode = 0x0004
	CreateConnection = 0x0005
	Disconnect = 0x0006
	AddSCOConnection = 0x0007
	AcceptConnectionRequest = 0x0009
	RejectConnectionRequest = 0x000A
	LinkKeyRequestReply = 0x000B
	LinkKeyRequestNegativeReply = 0x000C
	PINCodeRequestReply = 0x000D
	PINCodeRequestNegativeReply = 0x000E
	ChangeConnectionPacketType = 0x000F
	AuthenticationRequested = 0x0011
	SetConnectionEncryption = 0x0013
	ChangeConnectionLinkKey = 0x0015
	MasterLinkKey = 0x0017
	RemoteNameRequest = 0x0019
	ReadRemoteSupportedFeatures = 0x001B
	ReadRemoteVersionInformation = 0x001D
	ReadClockOffset = 0x001F


class LinkPolicyOpcode(OCF):
	HoldMode = 0x0001
	SniffMode = 0x0003
	ExitSniffMode = 0x0004
	ParkMode = 0x0005
	ExitParkMode = 0x0006
	QoSSetup = 0x0007
	RoleDiscovery = 0x0009
	SwitchRole = 0x000B
	ReadLinkPolicySettings = 0x000C
	WriteLinkPolicySettings = 0x000D


class HostControllerBasebandOpcode(OCF):
	SetEventMask = 0x0001
	Reset = 0x0003
	SetEventFilter = 0x0005
	Flush = 0x0008
	ReadPINType = 0x0009
	WritePINType = 0x000A
	CreateNewUnitKey = 0x000B
	ReadStoredLinkKey = 0x000D
	WriteStoredLinkKey = 0x0011
	DeleteStoredLinkKey = 0x0012
	ChangeLocalName = 0x0013
	ReadLocalName = 0x0014
	ReadConnectionAcceptTimeout = 0x0015
	WriteConnectionAcceptTimeout = 0x0016
	ReadPageTimeout = 0x0017
	WritePageTimeout = 0x0018
	ReadScanEnable = 0x0019
	WriteScanEnable = 0x001A
	ReadPageScanActivity = 0x001B
	WritePageScanActivity = 0x001C
	ReadInquiryScanActivity = 0x001D
	WriteInquiryScanActivity = 0x001E
	ReadAuthenticationEnable = 0x001F
	WriteAuthenticationEnable = 0x0020
	ReadEncryptionMode = 0x0021
	WriteEncryptionMode = 0x0022
	ReadClassOfDevice = 0x0023
	WriteClassOfDevice = 0x0024
	ReadVoiceSetting = 0x0025
	WriteVoiceSetting = 0x0026
	ReadAutomaticFlushTimeout = 0x0027
	WriteAutomaticFlushTimeout = 0x0028
	ReadNumBroadcastRetransmissions = 0x0029
	WriteNumBroadcastRetransmissions = 0x002A
	ReadHoldModeActivity = 0x002B
	WriteHoldModeActivity = 0x002C
	ReadTransmitPowerLevel = 0x002D
	ReadSCOFlowControlEnable = 0x002E
	WriteSCOFlowControlEnable = 0x002F
	SetHostControllerToHostFlowControl = 0x0031
	HostBufferSize = 0x0033
	HostNumberOfCompletedPackets = 0x0035
	ReadLinkSupervisionTimeout = 0x0036
	WriteLinkSupervisionTimeout = 0x0037
	ReadNumberOfSupportedIAC = 0x0038
	ReadCurrentIACLAP = 0x0039
	WriteCurrentIACLAP = 0x003A
	ReadPageScanPeriodMode = 0x003B
	WritePageScanPeriodMode = 0x003C
	ReadPageScanMode = 0x003D
	WritePageScanMode = 0x003E

class LEControllerOpcode(OCF):
	SetEventMask = 0x0001
	ReadBufferSize = 0x0002
	ReadLocalSupportedFeatures = 0x0003
	SetRandomAddress = 0x0005
	SetAdvertisingParameters = 0x0006
	ReadAdvertisingChannelTxPower = 0x0007
	SetAdvertisingData = 0x0008
	SetScanResponseData = 0x0009
	SetAdvertisingEnable = 0x000A
	SetScanParameters = 0x000B
	SetScanEnable = 0x000C
	CreateConnection = 0x000D
	CreateConnectionCancel = 0x000E
	ReadWhitelistSize = 0x000F
	ClearWhitelist = 0x0010
	AddDeviceToWhitelist = 0x0011
	RemoveDeviceFromWhitelist = 0x0012
	ConnectionUpdate = 0x0013
	SetHostChannelClassification = 0x0014
	ReadChannelMap = 0x0015
	ReadRemoteUsedFeatures = 0x0016
	Encrypt = 0x0017
	Rand = 0x0018
	StartEncryption = 0x0019
	LongTermKeyRequestReply = 0x001A
	LongTermKeyRequestNegativeReply = 0x001B
	ReadSupportedState = 0x001C
	ReceiverTest = 0x001D
	TransmitterTest = 0x001E
	TestEnd = 0x001F


def ogf_of_ocf(ocf: OCF) -> OGF:
	if isinstance(ocf, LEControllerOpcode):
		return OGF.LEController
	if isinstance(ocf, LinkPolicyOpcode):
		return OGF.LinkPolicy
	if isinstance(ocf, HostControllerBasebandOpcode):
		return OGF.HCIControlBandband
	if isinstance(ocf, LinkControlOpcode):
		return OGF.LinkControl
	raise NotImplementedError(f"unknown ocf: {ocf}")


class Opcode(ByteSerializable):
	__slots__ = "ogf", "ocf"

	def __init__(self, ogf: OGF, ocf: OCF) -> None:
		self.ogf = ogf
		self.ocf = ocf

	def to_bytes(self) -> bytes:
		if not isinstance(self.ocf.value, int):
			raise ValueError(f"expected ocf int not {self.ocf.value}")
		return (self.ogf.value | self.ocf.value).to_bytes(2, byteorder="little")

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Opcode':
		assert len(b) == 2
		ogf = OGF((b[0] & 0xFC) >> 2)
		ocf = OGFClasses[ogf]((b[0] & 0x03 << 8) | b[1])
		return cls(ogf, ocf)

	@classmethod
	def from_ocf(cls, ocf: OCF) -> 'Opcode':
		return cls(ogf_of_ocf(ocf), ocf)

	def __repr__(self) -> str:
		return f"Opcode({self.ogf}, {self.ocf}"


CommandParameterClasses: Dict[OGF, Dict[OCF, 'CommandParameters']] = dict()


def register_command_parameters(cls: TypeVar[CommandParameterClasses]):
	CommandParameterClasses[cls.Opcode.ogf][cls.Opcode.ocf] = cls
	return cls


class CommandParameters(ByteSerializable, abc.ABC):
	Opcode: ClassVar[Opcode]

	def parameters_to_bytes(self) -> bytes:
		raise NotImplementedError()

	def to_bytes(self) -> bytes:
		return self.to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'CommandParameters':
		"""
		from_bytes need to know the opcode (OGF and OCF) so use from_opcode_bytes instead
		:param b:
		:return:
		"""
		raise RuntimeError("from_bytes isn't implemented for command parameters on purpose")

	@classmethod
	def from_opcode_bytes(cls, opcode: Opcode, b: bytes) -> 'CommandParameters':
		classes = CommandParameterClasses[opcode.ogf]
		return classes[opcode.ocf].parameters_from_bytes(b)

	@classmethod
	def parameters_from_bytes(cls, b: bytes) -> 'CommandParameters':
		raise NotImplementedError()


class Command(ByteSerializable):
	__slots__ = "opcode", "parameters"

	def __init__(self, opcode: Opcode, parameters: CommandParameters) -> None:
		# MIGHT NEED TO BE FIXXED TO 31 bytes
		self.opcode = opcode
		self.parameters = parameters

	def to_bytes(self) -> bytes:
		return self.opcode.to_bytes() + self.parameters.to_bytes()

	@classmethod
	def from_bytes(cls, b: bytes) -> 'Command':
		opcode = Opcode.from_bytes(b[:2])
		parameters = CommandParameters.from_opcode_bytes(opcode, b[2:])
		return cls(opcode, parameters)

	def __repr__(self) -> str:
		return f"Command({self.opcode}, {self.parameters})"

class ErrorCode(enum.IntEnum):
	Ok = 0x00
	UnknownHCICommand = 0x01
	NoConnection = 0x02
	HardwareFailure = 0x03
	PageTimeout = 0x04
	AuthenticationFailure = 0x05
	KeyMissing = 0x06
	MemoryFull = 0x07
	ConnectionTimeout = 0x08
	MaxNumberOfConnections = 0x09
	MaxNumberOfSCOConnectionsToADevice = 0x0A
	ACLConnectionAlreadyExists = 0x0B
	CommandDisallowed = 0x0C
	HostRejectedDueToLimitedResources = 0x0D
	HostRejectedDueToSecurityReasons = 0x0E
	HostRejectedDueToARemoteDeviceOnlyAPersonalDevice = 0x0F
	HostTimeout = 0x1
	UnsupportedFeatureOrParameterValue = 0x11
	InvalidHCICommandParameters = 0x12
	OtherEndTerminatedConnectionUserEndedConnection = 0x13
	OtherEndTerminatedConnectionLowResources = 0x14
	OtherEndTerminatedConnectionAboutToPowerOff = 0x15
	ConnectionTerminatedByLocalHost = 0x16
	RepeatedAttempts = 0x17
	PairingNotAllowed = 0x18
	UnknownLMPPDU = 0x19
	UnsupportedRemoteFeature = 0x1A
	SCOOffsetRejected = 0x1B
	SCOIntervalRejected = 0x1C
	SCOAirModeRejected = 0x1D
	InvalidLMPParameters = 0x1E
	UnspecifiedError = 0x1F
	UnsupportedLMPParameter = 0x20
	RoleChangeNotAllowed = 0x21
	LMPResponseTimeout = 0x22
	LMPErrorTransactionCollision = 0x23
	LMPPDUNotAllowed = 0x24
	EncryptionModeNotAcceptable = 0x25
	UnitKeyUsed = 0x26
	QoSNotSupported = 0x27
	InstantPassed = 0x28
	PairingWithUnitKeyNotSupported = 0x29

package rawtls

import (
	"errors"
	"fmt"
	"io"
)

type (
	ContentType      uint8
	HandshakeType    uint8
	ExtensionType    uint16
	ProtocolVersion  uint16
	CipherSuite      uint16
	KeyGroup         uint16
	SignatureScheme  uint16
	AlertLevel       uint8
	AlertDescription uint8
	NameType         uint8

	Ext struct {
		Type   ExtensionType
		Length uint16
		Offset uint16
	}

	Key struct {
		Group  KeyGroup
		Length uint16
		Offset uint16
	}

	BytesRange struct {
		S, E uint16 // start, end
	}

	ints interface {
		~int | ~uint8 | ~uint16 | ~uint32
	}

	ints16 interface {
		~int | ~uint16 | ~uint32
	}

	ints32 interface {
		~int | ~uint32
	}
)

// Record content types.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
const (
	RecInvalid          ContentType = 0x00
	RecChangeCipherSpec ContentType = 0x14
	RecAlert            ContentType = 0x15
	RecHandshake        ContentType = 0x16
	RecAppData          ContentType = 0x17
	RecHeartbeat        ContentType = 0x18 // RFC6520
)

// Handshake message types.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4
const (
	MsgClientHello           HandshakeType = 0x01
	MsgServerHello           HandshakeType = 0x02
	MsgNewSessionTicket      HandshakeType = 0x04
	MsgEndOfEarlyData        HandshakeType = 0x05
	MsgEncryptedExtensions   HandshakeType = 0x08
	MsgCertificate           HandshakeType = 0x0b
	MsgCertificateRequest    HandshakeType = 0x0d
	MsgCertificateVerify     HandshakeType = 0x0f
	MsgFinished              HandshakeType = 0x14
	MsgKeyUpdate             HandshakeType = 0x18
	MsgCompressedCertificate HandshakeType = 0x19 // RFC 8879
	MsgMessageHash           HandshakeType = 0xfe
)

// Extension types.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
const (
	ExtServerName                 ExtensionType = 0x0000
	ExtMaxFragmentLength          ExtensionType = 0x0001
	ExtStatusRequest              ExtensionType = 0x0005
	ExtSupportedGroups            ExtensionType = 0x000a
	ExtSignatureAlgorithms        ExtensionType = 0x000d
	ExtUseSRTP                    ExtensionType = 0x000e
	ExtHeartbeat                  ExtensionType = 0x000f
	ExtALPN                       ExtensionType = 0x0010
	ExtSignedCertificateTimestamp ExtensionType = 0x0012
	ExtClientCertificateType      ExtensionType = 0x0013
	ExtServerCertificateType      ExtensionType = 0x0014
	ExtPadding                    ExtensionType = 0x0015
	ExtPreSharedKey               ExtensionType = 0x0029
	ExtEarlyData                  ExtensionType = 0x002a
	ExtSupportedVersions          ExtensionType = 0x002b
	ExtCookie                     ExtensionType = 0x002c
	ExtPSKKeyExchangeModes        ExtensionType = 0x002d
	ExtCertificateAuthorities     ExtensionType = 0x002f
	ExtOIDFilters                 ExtensionType = 0x0030
	ExtPostHandshakeAuth          ExtensionType = 0x0031
	ExtSignatureAlgorithmsCert    ExtensionType = 0x0032
	ExtKeyShare                   ExtensionType = 0x0033

	// Seen on the wire, defined elsewhere.

	ExtExtendedMasterSecret ExtensionType = 0x0017 // RFC7627
	ExtCompressCertificate  ExtensionType = 0x001b // RFC8879
	ExtRecordSizeLimit      ExtensionType = 0x001c // RFC8449
	ExtSessionTicket        ExtensionType = 0x0023 // RFC5077
	ExtApplicationSettings  ExtensionType = 0x4469 // draft-vvv-tls-alps
	ExtEncryptedClientHello ExtensionType = 0xfe0d // draft-ietf-tls-esni
	ExtRenegotiationInfo    ExtensionType = 0xff01 // RFC5746
)

// Cipher suites.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4
const (
	TLS_AES_128_GCM_SHA256       CipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384       CipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 CipherSuite = 0x1303
	TLS_AES_128_CCM_SHA256       CipherSuite = 0x1304
	TLS_AES_128_CCM_8_SHA256     CipherSuite = 0x1305

	// Signaling cipher suite values, not real suites.

	TLS_EMPTY_RENEGOTIATION_INFO_SCSV CipherSuite = 0x00ff // RFC5746
	TLS_FALLBACK_SCSV                 CipherSuite = 0x5600 // RFC7507
)

// Protocol versions.
const (
	VerTLS10 ProtocolVersion = 0x0301
	VerTLS11 ProtocolVersion = 0x0302
	VerTLS12 ProtocolVersion = 0x0303
	VerTLS13 ProtocolVersion = 0x0304
)

// Supported groups and key share groups.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
const (
	GroupSecp256r1 KeyGroup = 0x0017
	GroupSecp384r1 KeyGroup = 0x0018
	GroupSecp521r1 KeyGroup = 0x0019
	GroupX25519    KeyGroup = 0x001d
	GroupX448      KeyGroup = 0x001e
	GroupFFDHE2048 KeyGroup = 0x0100
	GroupFFDHE3072 KeyGroup = 0x0101
	GroupFFDHE4096 KeyGroup = 0x0102
	GroupFFDHE6144 KeyGroup = 0x0103
	GroupFFDHE8192 KeyGroup = 0x0104

	GroupX25519MLKEM768 KeyGroup = 0x11ec // draft-kwiatkowski-tls-ecdhe-mlkem
)

// Signature schemes.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
const (
	SigRSAPKCS1SHA256       SignatureScheme = 0x0401
	SigRSAPKCS1SHA384       SignatureScheme = 0x0501
	SigRSAPKCS1SHA512       SignatureScheme = 0x0601
	SigECDSASecp256r1SHA256 SignatureScheme = 0x0403
	SigECDSASecp384r1SHA384 SignatureScheme = 0x0503
	SigECDSASecp521r1SHA512 SignatureScheme = 0x0603
	SigRSAPSSRSAeSHA256     SignatureScheme = 0x0804
	SigRSAPSSRSAeSHA384     SignatureScheme = 0x0805
	SigRSAPSSRSAeSHA512     SignatureScheme = 0x0806
	SigEd25519              SignatureScheme = 0x0807
	SigEd448                SignatureScheme = 0x0808
	SigRSAPSSPSSSHA256      SignatureScheme = 0x0809
	SigRSAPSSPSSSHA384      SignatureScheme = 0x080a
	SigRSAPSSPSSSHA512      SignatureScheme = 0x080b

	// Legacy, TLS 1.2 only.

	SigRSAPKCS1SHA1 SignatureScheme = 0x0201
	SigECDSASHA1    SignatureScheme = 0x0203
)

// Alert levels and descriptions.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-6
const (
	AlertLevelWarning AlertLevel = 1
	AlertLevelFatal   AlertLevel = 2

	AlertCloseNotify              AlertDescription = 0
	AlertUnexpectedMessage        AlertDescription = 10
	AlertBadRecordMAC             AlertDescription = 20
	AlertRecordOverflow           AlertDescription = 22
	AlertHandshakeFailure         AlertDescription = 40
	AlertBadCertificate           AlertDescription = 42
	AlertUnsupportedCertificate   AlertDescription = 43
	AlertCertificateRevoked       AlertDescription = 44
	AlertCertificateExpired       AlertDescription = 45
	AlertCertificateUnknown       AlertDescription = 46
	AlertIllegalParameter         AlertDescription = 47
	AlertUnknownCA                AlertDescription = 48
	AlertAccessDenied             AlertDescription = 49
	AlertDecodeError              AlertDescription = 50
	AlertDecryptError             AlertDescription = 51
	AlertProtocolVersion          AlertDescription = 70
	AlertInsufficientSecurity     AlertDescription = 71
	AlertInternalError            AlertDescription = 80
	AlertInappropriateFallback    AlertDescription = 86
	AlertUserCanceled             AlertDescription = 90
	AlertMissingExtension         AlertDescription = 109
	AlertUnsupportedExtension     AlertDescription = 110
	AlertUnrecognizedName         AlertDescription = 112
	AlertBadCertificateStatusResp AlertDescription = 113
	AlertUnknownPSKIdentity       AlertDescription = 115
	AlertCertificateRequired      AlertDescription = 116
	AlertNoApplicationProtocol    AlertDescription = 120
)

// Server name types.
//
//	RFC6066: https://datatracker.ietf.org/doc/html/rfc6066#section-3
const (
	NameHostName NameType = 0x00
)

var (
	ErrFragmented  = errors.New("fragmented message")
	ErrShortBuffer = io.ErrShortBuffer
	ErrUnexpected  = errors.New("unexpected message")
	ErrMalformed   = errors.New("malformed message")
	ErrUnsupported = errors.ErrUnsupported
	ErrShutdown    = errors.New("protocol is shutdown")
)

var zeroRange BytesRange

// HelloRetryRequestRandom is the ServerHello random marking HelloRetryRequest,
// SHA-256 of "HelloRetryRequest".
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
var HelloRetryRequestRandom = [32]byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

func (a AlertDescription) Error() string { return fmt.Sprintf("alert:%d", int(a)) }

package stun

type Attributes []RawAttribute

type AttrType uint16

func (t AttrType) Required() bool {
	return t <= 0x7fff
}

func (t AttrType) Optional() bool {
	return t >= 0x8000
}

func (t AttrType) Value() uint16 {
	return uint16(t)
}

// Attributes from comprehension-required range (0x0000-0x7FFF).
const (
	AttrMappedAddress     AttrType = 0x0001 // MAPPED-ADDRESS
	AttrUsername          AttrType = 0x0006 // USERNAME
	AttrMessageIntegrity  AttrType = 0x0008 // MESSAGE-INTEGRITY
	AttrErrorCode         AttrType = 0x0009 // ERROR-CODE
	AttrUnknownAttributes AttrType = 0x000A // UNKNOWN-ATTRIBUTES
	AttrRealm             AttrType = 0x0014 // REALM
	AttrNonce             AttrType = 0x0015 // NONCE
	AttrXORMappedAddress  AttrType = 0x0020 // XOR-MAPPED-ADDRESS
)

// Attributes from comprehension-optional range (0x8000-0xFFFF).
const (
	AttrSoftware        AttrType = 0x8022 // SOFTWARE
	AttrAlternateServer AttrType = 0x8023 // ALTERNATE-SERVER
	AttrFingerprint     AttrType = 0x8028 // FINGERPRINT
)

// Attributes from RFC 5245 ICE.
const (
	AttrPriority       AttrType = 0x0024 // PRIORITY
	AttrUseCandidate   AttrType = 0x0025 // USE-CANDIDATE
	AttrICEControlled  AttrType = 0x8029 // ICE-CONTROLLED
	AttrICEControlling AttrType = 0x802A // ICE-CONTROLLING
)

// Attributes from RFC 5766 TURN.
const (
	AttrChannelNumber      AttrType = 0x000C // CHANNEL-NUMBER
	AttrLifetime           AttrType = 0x000D // LIFETIME
	AttrXORPeerAddress     AttrType = 0x0012 // XOR-PEER-ADDRESS
	AttrData               AttrType = 0x0013 // DATA
	AttrXORRelayedAddress  AttrType = 0x0016 // XOR-RELAYED-ADDRESS
	AttrEvenPort           AttrType = 0x0018 // EVEN-PORT
	AttrRequestedTransport AttrType = 0x0019 // REQUESTED-TRANSPORT
	AttrDontFragment       AttrType = 0x001A // DONT-FRAGMENT
	AttrReservationToken   AttrType = 0x0022 // RESERVATION-TOKEN
)

// Attributes from RFC 5780 NAT Behavior Discovery
const (
	AttrChangeRequest  AttrType = 0x0003 // CHANGE-REQUEST
	AttrPadding        AttrType = 0x0026 // PADDING
	AttrResponsePort   AttrType = 0x0027 // RESPONSE-PORT
	AttrCacheTimeout   AttrType = 0x8027 // CACHE-TIMEOUT
	AttrResponseOrigin AttrType = 0x802b // RESPONSE-ORIGIN
	AttrOtherAddress   AttrType = 0x802C // OTHER-ADDRESS
)

// Attributes from RFC 3489, removed by RFC 5389,
//
//	but still used by RFC5389-implementing software like Vovida.org, reTURNServer, etc.
const (
	AttrSourceAddress  AttrType = 0x0004 // SOURCE-ADDRESS
	AttrChangedAddress AttrType = 0x0005 // CHANGED-ADDRESS
)

// Attributes from RFC 6062 TURN Extensions for TCP Allocations.
const (
	AttrConnectionID AttrType = 0x002a // CONNECTION-ID
)

// Attributes from RFC 6156 TURN IPv6.
const (
	AttrRequestedAddressFamily AttrType = 0x0017 // REQUESTED-ADDRESS-FAMILY
)

// Attributes from An Origin Attribute for the STUN Protocol.
const (
	AttrOrigin AttrType = 0x802F
)

// Attributes from RFC 8489 STUN.
const (
	AttrMessageIntegritySHA256 AttrType = 0x001C // MESSAGE-INTEGRITY-SHA256
	AttrPasswordAlgorithm      AttrType = 0x001D // PASSWORD-ALGORITHM
	AttrUserhash               AttrType = 0x001E // USERHASH
	AttrPasswordAlgorithms     AttrType = 0x8002 // PASSWORD-ALGORITHMS
	AttrAlternateDomain        AttrType = 0x8003 // ALTERNATE-DOMAIN
)

type RawAttribute struct {
	Type   AttrType
	Length uint16
	Value  []byte
}

func (a RawAttribute) AddTo(m *Message) error {
	m.Add(a.Type, a.Value)
	return nil
}

const padding = 4

func nearestPaddedValueLength(l int) int {
	n := padding * (l / padding)
	if n < l {
		n += padding
	}
	return n
}

func compatAttrType(v uint16) AttrType {
	if v == 0x8020 {
		return AttrXORMappedAddress
	}
	return AttrType(v)
}

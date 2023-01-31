package stun

import (
	"crypto/rand"
	"encoding/base64"
)

const(
		// Defined in "STUN Message Structure", section 6.
	magicCookie         = 0x2112A442
	attributeHeaderSize = 4
	messageHeaderSize   = 20

	// TransactionIDSize is length of transaction id array (in bytes).
	TransactionIDSize = 12 // 96 bit
)

func NewTransactionID() (b [TransactionIDSize]byte) {
	readFullOrPanic(rand.Reader, b[:])
	return b
}

func IsMessage(b []byte) bool {
	return len(b) >= messageHeaderSize && bin.Uint32(b[4:8]) == magicCookie 
}

func New() *Message {
	const defaultRawCapacity = 120
	return &Message{
		Raw: make([]byte,messageHeaderSize,defaultRawCapacity)
	}
}

type Message struct{
	Type MessageType
	Length uint32
	TransactionID [TransactionIDSize]byte
	Attributes Attributes 
}

func (m *Message) MarshalBinary() (data []byte ,err error){
	b := make([]byte,len(m.Raw))
	copy(b,m.Raw)
	return b, nil
}

func (m *Message) UnMarshalBinary(data []byte) error{
	m.append(m.Raw[:0],data...)
	return m.Decode()
}

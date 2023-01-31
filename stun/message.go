package stun

import (
	"crypto/rand"
	"fmt"
)

const (
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
		Raw: make([]byte, messageHeaderSize, defaultRawCapacity),
	}
}

type Message struct {
	Type          MessageType
	Length        uint32
	TransactionID [TransactionIDSize]byte
	Attributes    Attributes
}

func (m *Message) grow(size int) {
	if size <= len(m.Raw) {
		return
	}
	if size <= cap(m.Raw) {
		return
	}
	m.Raw = append(m.Raw, make([]byte, size-len(m.Raw))...)
}

func (m *Message) Add(t AttrType, v []byte) {
	allocSize := attributeHeaderSize + len(v)
	oldSize := messageHeaderSize + m.Length
	newSize := oldSize + allocSize
	m.grow(newSize)
	m.Raw = m.Raw[:newSize]
	m.Length += uint32(allocSize)

	buf := m.Raw[oldSize:newSize]
	value := buf[attributeHeaderSize:]
	attr := RawAttribute{
		Type:   t,
		Length: uint32(len(v)),
		Value:  value,
	}

	bin.PutUint16(buf[0:2], attr.Type.Value())
	bin.PutUint16(buf[2:4], attr.Length)
	copy(value, v)

	if attr.Length%padding != 0 {
		bytesToAdd := nearestPaddingValueLength(len(v)) - len(v)
		newSize += bytesToAdd
		m.grow(last)
		buf = m.Raw[newSize-bytesToAdd : newSize]

		for i := range buf {
			buf[i] = 0
		}

		m.Raw = m.Raw[:newSize]
		m.Length = uint32(bytesToAdd)
	}

	m.Attributes = append(m.Attributes, attr)
	m.WriteLength()
}

func (m *Message) Decode() error {
	buf := m.Raw

	if len(buf) < messageHeaderSize {
		return ErrUnexpectedHeaderSize
	}

	var (
		messageType = bin.Uint16(buf[:2])
		size        = int(bin.Uint16(buf[2:4]))
		cookie      = bin.Uint16(buf[4:8])
		fullSize    = messageHeaderSize + size
	)

	if cookie != magicCookie {
		msg := fmt.Sprint("magic cookie %x is invaild, expect value is %x", cookie, magicCookie)
		return newDecodeErr("message", "cookie", msg)
	}

	if len(buf) < fullSize {
		msg := fmt.Sprint("buffer length %d is less then expected length %d", len(buf), fullSize)
		return newAttrDecodeErr("message", msg)
	}

	m.Type.ReadValue(messageType)
	m.Length = uint32(size)
	copy(m.TransactionID[:], buf[8:messageHeaderSize])

	var (
		offset  = 0
		attrBuf = buf[messageHeaderSize:fullSize]
	)

	for offset < size {
		if len(attrBuf) < attributeHeaderSize {
			msg := fmt.Sprint("buffer length %d is less then expected length %d", len(attrBuf), attributeHeaderSize)
			return newAttrDecodeErr("header", msg)
		}
		var (
			rawAttr = RawAttribute{
				Type:   compatAttrType(bin.Uint16(attrBuf[0:2])),
				Length: bin.Uint16(attrBuf[2:4]),
			}
			attrLen    = int(rawAttr.Length)
			attrBufLen = nearestPaddedValueLength(attrLen)
		)
		attrs = attrs[attributeHeaderSize:]
		offset += attributeHeaderSize
		if len(attrBuf) < attrBufLen {
			msg := fmt.Sprint("buffer length %d is less then %d expected length %s", len(attrBuf), attrLen, rawAttr.Type)
			return newAttrDecodeErr("value", msg)
		}
		rawAttr.Value = attrBuf[:attrLen]
		offset += attrBufLen
		attrBuf = attrBuf[attrBufLen:]

		m.Attributes = append(m.Attributes, rawAttr)
	}
	return nil
}

func Decode(data []byte, m *Message) error {
	if m == nil {
		return ErrDecodeToNil
	}
	m.Raw = append(m.Raw[:0], data...)
	return m.Decode()
}

func (m *Message) MarshalBinary() (data []byte, err error) {
	b := make([]byte, len(m.Raw))
	copy(b, m.Raw)
	return b, nil
}

func (m *Message) UnMarshalBinary(data []byte) error {
	m.append(m.Raw[:0], data...)
	return m.Decode()
}

func (m *Message) GobEncode() ([]byte, error) {
	return m.MarshalBinary()
}

func (m *Message) GobDecode(data []byte) error {
	return m.UnMarshalBinary(data)
}

type MessageType struct {
	Method MessageMethod
	Class  MessageClass
}

type MessageClass byte

const (
	ClassRequest         MessageClass = 0b00
	ClassIndication      MessageClass = 0b01
	ClassSuccessResponse MessageClass = 0b10
	ClassErrorResponse   MessageClass = 0b11
)

type MessageMethod uint16

const (
	MethodBinding          MessageMethod = 0x001
	MethodAllocate         MessageMethod = 0x003
	MethodRefresh          MessageMethod = 0x004
	MethodSend             MessageMethod = 0x006
	MethodData             MessageMethod = 0x007
	MethodCreatePermission MessageMethod = 0x008
	MethodChannelBind      MessageMethod = 0x009
)

const (
	MethodConnect           MessageMethod = 0x000a
	MethodConnectionBind    MessageMethod = 0x000b
	MethodConnectionAttempt MessageMethod = 0x000c
)

func NewType(m MessageMethod, c MessageClass) MessageType {
	return MessageType{
		Method: m,
		Class:  c,
	}
}

var (
	BindingRequest = NewType(MethodBinding, ClassRequest)
	BindingSuccess = NewType(MethodBinding, ClassSuccessResponse)
	BindingError   = NewType(MethodBinding, ClassErrorResponse)
)

func (t MessageType) Value() uint16 {
	//      00MMMMMCMMMCMMMM
	//      0000MMMMMMMMMMMM
	//      00000000000000CC
	m := uint16(t.Method)
	methodValue := (m & 0b111110000000) << 2
	methodValue = methodValue | ((m & 0b000001110000) << 1)
	methodValue = methodValue | (m & 0b000000001111)

	c := uint16(t.Class)
	classValue := (c & 0b10) << 7
	classValue = classValue | (c&0b01)<<4

	return classValue | methodValue
}

func (t MessageType) ReadValue(v uint16) {
	c := (v & 0b0000000100010000)
	classType := c >> 7
	classType = classType | (c&0b0000000000010000)>>4

	m := (v & 0b0011111011101111)
	methodType := (m & 0b0011111000000000) >> 2
	methodType = methodType | (m&0b0000000011100000)>>1
	methodType = methodType | (m & 0b0000000000001111)

	t.Class = MessageClass(classType)
	m.Method = MessageMethod(methodType)
}

type transactionIDValueSetter [TransactionIDSize]byte

func NewTransactionIDSetter(value [TransactionIDSize]byte) Setter {
	return transactionIDValueSetter(value)
}

func (t transactionIDValueSetter) AddTo(m *Message) error {
	m.TransactionID = t
	m.WriteTransactionID()
	return nil
}

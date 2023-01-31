package stun

import (
	"encoding/binary"
	"io"
)

// bin is shorthand to binary.BigEndian.
var bin = binary.BigEndian // nolint:gochecknoglobals

func readFullOrPanic(r io.Reader, v []byte) int {
	n, err := io.ReadFull(r, v)
	if err != nil {
		panic(err) // nolint
	}
	return n
}

func writeOrPanic(w io.Writer, v []byte) int {
	n, err := w.Write(v)
	if err != nil {
		panic(err) // nolint
	}
	return n
}

// IANA assigned ports for "stun" protocol.
const (
	DefaultPort    = 3478
	DefaultTLSPort = 5349
)

type transactionIDSetter struct{}

func (transactionIDSetter) AddTo(m *Message) error {
	return m.NewTransactionID()
}

// TransactionID is Setter for m.TransactionID.
var TransactionID Setter = transactionIDSetter{}

package stun

import (
	"errors"
)

var (
	ErrDecodeToNil          = errors.New("Can't decode nil (empty) message")
	ErrUnexpectedHeaderSize = errors.New("Not enough bytes in header")
	ErrAttributeNotFound    = errors.New("Attribute not found")
)

type DecodeErr struct {
	Place   DecodeErrPlace
	Message string
}

type DecodeErrPlace struct {
	Parent   string
	Children string
}

func newDecodeErr(parent, children, message string) *DecodeErr {
	return &DecodeErr{
		Place:   DecodeErrPlace{Parent: parent, Children: children},
		Message: message,
	}
}

func newAttrDecodeErr(children, message string) *DecodeErr {
	return newDecodeErr("attribute", children, message)
}

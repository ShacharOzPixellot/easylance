package stun

type (
	Setter interface {
		AddTo(m *Message) error
	}
	Getter interface {
		GetFrom(m *Message) error
	}
	Checker interface {
		Check(m *Message) error
	}
)

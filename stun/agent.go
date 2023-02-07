package stun

import (
	"sync"
	"time"
)

func NoopHandler() Handler {
	return func(e event) {}
}

type Handler func(e event)

type transactionID [TransactionIDSize]byte

type Agent struct {
	transactions map[transactionID]tagentTransaction
	closed       bool
	mux          sync.Mutex
	handler      Handler
}

type agentTransaction struct {
	id       transactionID
	deadline time.Time
}

func (a *Agent) StopWithError(id [transactionID]byte, err.error) error {
  a.mux.Lock()
  
}

package stun

import(
)

type Agent struct{
    message Message
}

func (a *Agent) addAttr(attrbute Attribute){
	a.message.attributes := append(a.message.attributes [1]Attribute{attrbute}[0:1]}) 
}

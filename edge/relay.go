package edge

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/instructions"
)

type Realay interface {
	Receive() instructions.Instruction
	Subscribe(crypto.Token) error
	Close()
}

type Gateway interface {
	Publish(instructions.Instruction)
	PublishOnWallet(instructions.Instruction, crypto.Token)
	CurrentFee() uint64
	Close()
}

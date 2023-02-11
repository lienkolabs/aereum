package instructions

import "github.com/lienkolabs/aereum/core/crypto"

const (
	ITransfer byte = iota
	IDeposit
	IWithdraw
	IJoinNetwork
	IUpdateInfo
	ICreateStage
	IJoinStage
	IAcceptJoinRequest
	IContent
	IUpdateStage
	IGrantPowerOfAttorney
	IRevokePowerOfAttorney
	ISponsorshipOffer
	ISponsorshipAcceptance
	ICreateEphemeral
	ISecureChannel
	IReact
	iUnkown
)

// Decorates instruction with its bytes hash.
type HashInstruction struct {
	Instruction Instruction
	Hash        crypto.Hash
}

// Instruction is the base interface that encompass all possible instructions
// defined for aereum protocol.
type Instruction interface {
	Validate(InstructionValidator) bool
	Payments() *Payment
	Serialize() []byte
	Epoch() uint64
	Kind() byte
	JSON() string
	Authority() crypto.Token
}

// ParseInstructions tries to parse a byte slice into an valid instruction.
// Instructions are not validated according to blockchain state at this stage,
// but signatures are checked.
func ParseInstruction(data []byte) Instruction {
	if data[0] != 0 {
		return nil
	}
	switch data[1] {
	case IJoinStage:
		return ParseJoinStage(data)
	case IContent:
		return ParseContent(data)
	case ITransfer:
		return ParseTransfer(data)
	case IDeposit:
		return ParseDeposit(data)
	case IWithdraw:
		return ParseWithdraw(data)
	case IReact:
		return ParseReact(data)
	}
	return nil
}

func InstructionKind(msg []byte) byte {
	if len(msg) < 2 {
		return iUnkown
	}
	return msg[1]
}

package instructions

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/util"
)

type CreateStage struct {
	EpochStamp      uint64
	Author          crypto.Token
	Stage           crypto.Token
	Submission      crypto.Token
	Moderation      crypto.Token
	Flag            byte
	Description     string
	Attorney        crypto.Token
	Signature       crypto.Signature
	Wallet          crypto.Token
	Fee             uint64
	WalletSignature crypto.Signature
}

func (create *CreateStage) Authority() crypto.Token {
	return create.Author
}

func (create *CreateStage) Epoch() uint64 {
	return create.EpochStamp
}

func (create *CreateStage) Kind() byte {
	return ICreateStage
}

func (create *CreateStage) Payments() *Payment {
	if create.Wallet != crypto.ZeroToken {
		return NewPayment(crypto.HashToken(create.Wallet), create.Fee)
	}
	if create.Attorney != crypto.ZeroToken {
		return NewPayment(crypto.HashToken(create.Wallet), create.Fee)
	}
	return NewPayment(crypto.HashToken(create.Author), create.Fee)
}

func (create *CreateStage) Serialize() []byte {
	bytes := create.serializeWalletSign()
	util.PutSignature(create.WalletSignature, &bytes)
	return bytes
}

func (stage *CreateStage) Validate(v InstructionValidator) bool {
	if !v.HasMember(crypto.HashToken(stage.Author)) {
		return false
	}
	audienceHash := crypto.HashToken(stage.Stage)
	if stage := v.GetAudienceKeys(audienceHash); stage != nil {
		return false
	}
	if v.CanPay(stage.Payments()) {
		stageKeys := StageKeys{
			Moderate: stage.Moderation,
			Submit:   stage.Submission,
			Stage:    stage.Stage,
			Flag:     stage.Flag,
		}
		if v.SetNewAudience(audienceHash, stageKeys) {
			v.AddFeeCollected(stage.Fee)
			return true
		}
	}
	return false
}

func (create *CreateStage) JSON() string {
	bulk := genericJSON(ICreateStage, create.EpochStamp, create.Fee, create.Author, create.Wallet, create.Attorney,
		create.Signature, create.WalletSignature)
	bulk.PutHex("stage", create.Stage[:])
	bulk.PutHex("submission", create.Submission[:])
	bulk.PutHex("moderation", create.Moderation[:])
	bulk.PutUint64("flag", uint64(create.Flag))
	bulk.PutString("description", create.Description)
	return bulk.ToString()
}

func (create *CreateStage) serialiazeSign() []byte {
	bytes := []byte{0, IReact}
	util.PutUint64(create.EpochStamp, &bytes)
	util.PutToken(create.Author, &bytes)
	util.PutToken(create.Stage, &bytes)
	util.PutToken(create.Submission, &bytes)
	util.PutToken(create.Moderation, &bytes)
	util.PutByte(create.Flag, &bytes)
	util.PutString(create.Description, &bytes)
	util.PutToken(create.Attorney, &bytes)
	return bytes
}

func (create *CreateStage) serializeWalletSign() []byte {
	bytes := create.serialiazeSign()
	util.PutSignature(create.Signature, &bytes)
	util.PutToken(create.Wallet, &bytes)
	util.PutUint64(create.Fee, &bytes)
	return bytes
}

func ParseCreateStage(data []byte) *CreateStage {
	var position int
	if data[0] != 0 || data[1] != ICreateStage {
		return nil
	}
	join := CreateStage{}
	join.EpochStamp, join.Author, position = parseHeader(data)
	join.Stage, position = util.ParseToken(data, position)
	join.Submission, position = util.ParseToken(data, position)
	join.Moderation, position = util.ParseToken(data, position)
	join.Flag, position = util.ParseByte(data, position)
	join.Description, position = util.ParseString(data, position)
	join.Attorney, position = util.ParseToken(data, position)
	msg := data[0:position]
	join.Signature, position = util.ParseSignature(data, position)
	if !checkSignature(msg, join.Signature, join.Attorney, join.Author) {
		return nil
	}
	join.Wallet, position = util.ParseToken(data, position)
	join.Fee, position = util.ParseUint64(data, position)
	msg = data[0:position]
	join.WalletSignature, position = util.ParseSignature(data, position)
	if !checkWalletSignature(msg, join.WalletSignature, join.Wallet, join.Attorney, join.Author) {
		return nil
	}
	if position != len(data) {
		return nil
	}
	return &join
}

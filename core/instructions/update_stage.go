package instructions

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/util"
)

type UpdateStage struct {
	EpochStamp      uint64
	Author          crypto.Token
	Stage           crypto.Token // existing audience public token - it doesn't change
	Submission      crypto.Token // new submission public token
	Moderation      crypto.Token // new moderation public token
	DiffHellKey     crypto.Token
	Flag            byte
	Description     string
	ReadMembers     crypto.TokenCiphers
	SubMembers      crypto.TokenCiphers
	ModMembers      crypto.TokenCiphers
	StageSignature  crypto.Signature
	Attorney        crypto.Token
	Signature       crypto.Signature
	Wallet          crypto.Token
	Fee             uint64
	WalletSignature crypto.Signature
}

func (update *UpdateStage) Authority() crypto.Token {
	return update.Author
}

func (update *UpdateStage) Epoch() uint64 {
	return update.EpochStamp
}

func (update *UpdateStage) Kind() byte {
	return IUpdateStage
}

func (update *UpdateStage) Payments() *Payment {
	if update.Wallet != crypto.ZeroToken {
		return NewPayment(crypto.HashToken(update.Wallet), update.Fee)
	}
	if update.Attorney != crypto.ZeroToken {
		return NewPayment(crypto.HashToken(update.Wallet), update.Fee)
	}
	return NewPayment(crypto.HashToken(update.Author), update.Fee)
}

func (update *UpdateStage) Serialize() []byte {
	bytes := update.serializeWalletSign()
	util.PutSignature(update.WalletSignature, &bytes)
	return bytes
}

func (update *UpdateStage) Validate(v InstructionValidator) bool {
	if !v.HasMember(crypto.HashToken(update.Author)) {
		return false
	}
	audienceHash := crypto.HashToken(update.Stage)
	if stage := v.GetAudienceKeys(audienceHash); stage != nil {
		return false
	}
	if v.CanPay(update.Payments()) {
		stageKeys := StageKeys{
			Moderate: update.Moderation,
			Submit:   update.Submission,
			Stage:    update.Stage,
			Flag:     update.Flag,
		}
		if v.SetNewAudience(audienceHash, stageKeys) {
			v.AddFeeCollected(update.Fee)
			return true
		}
	}
	return false
}

func (update *UpdateStage) JSON() string {
	bulk := genericJSON(IUpdateStage, update.EpochStamp, update.Fee, update.Author, update.Wallet, update.Attorney,
		update.Signature, update.WalletSignature)
	bulk.PutHex("stage", update.Stage[:])
	bulk.PutHex("submission", update.Submission[:])
	bulk.PutHex("moderation", update.Moderation[:])
	bulk.PutUint64("flag", uint64(update.Flag))
	bulk.PutString("description", update.Description)
	return bulk.ToString()
}

func (update *UpdateStage) serialiazeStageSign() []byte {
	bytes := []byte{0, IReact}
	util.PutUint64(update.EpochStamp, &bytes)
	util.PutToken(update.Author, &bytes)
	util.PutToken(update.Stage, &bytes)
	util.PutToken(update.Submission, &bytes)
	util.PutToken(update.Moderation, &bytes)
	util.PutByte(update.Flag, &bytes)
	util.PutString(update.Description, &bytes)
	util.PutTokenCiphers(update.ReadMembers, &bytes)
	util.PutTokenCiphers(update.SubMembers, &bytes)
	util.PutTokenCiphers(update.ModMembers, &bytes)
	return bytes
}

func (update *UpdateStage) serializeSign() []byte {
	bytes := update.serialiazeStageSign()
	util.PutSignature(update.StageSignature, &bytes)
	util.PutToken(update.Attorney, &bytes)
	return bytes
}

func (update *UpdateStage) serializeWalletSign() []byte {
	bytes := update.serializeSign()
	util.PutSignature(update.Signature, &bytes)
	util.PutToken(update.Wallet, &bytes)
	util.PutUint64(update.Fee, &bytes)
	return bytes
}

func ParseUpdateStage(data []byte) *UpdateStage {
	var position int
	if data[0] != 0 || data[1] != IUpdateStage {
		return nil
	}
	join := UpdateStage{}
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

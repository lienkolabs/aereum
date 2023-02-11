package instructions

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/util"
)

type JoinStage struct {
	EpochStamp      uint64
	Author          crypto.Token
	Stage           crypto.Token
	DiffHellKey     crypto.Token
	Presentation    string
	Attorney        crypto.Token
	Signature       crypto.Signature
	Wallet          crypto.Token
	Fee             uint64
	WalletSignature crypto.Signature
}

func (join *JoinStage) Authority() crypto.Token {
	return join.Author
}

func (join *JoinStage) Epoch() uint64 {
	return join.EpochStamp
}

func (join *JoinStage) Kind() byte {
	return IJoinStage
}

func (join *JoinStage) Payments() *Payment {
	if join.Wallet != crypto.ZeroToken {
		return NewPayment(crypto.HashToken(join.Wallet), join.Fee)
	}
	if join.Attorney != crypto.ZeroToken {
		return NewPayment(crypto.HashToken(join.Wallet), join.Fee)
	}
	return NewPayment(crypto.HashToken(join.Author), join.Fee)
}

func (join *JoinStage) Serialize() []byte {
	bytes := join.serializeWalletSign()
	util.PutSignature(join.WalletSignature, &bytes)
	return bytes
}

func (join *JoinStage) Validate(v InstructionValidator) bool {
	if !v.HasMember(crypto.HashToken(join.Author)) {
		return false
	}
	if keys := v.GetAudienceKeys(crypto.HashToken(join.Stage)); keys == nil {
		return false
	}
	if v.CanPay(join.Payments()) {
		v.AddFeeCollected(join.Fee)
		return true
	}
	return false
}

func (join *JoinStage) JSON() string {
	bulk := genericJSON(IJoinStage, join.EpochStamp, join.Fee, join.Author, join.Wallet, join.Attorney,
		join.Signature, join.WalletSignature)
	bulk.PutHex("stage", join.Stage[:])
	bulk.PutString("presentation", join.Presentation)
	bulk.PutHex("diffieHellmanKey", join.DiffHellKey[:])
	return bulk.ToString()
}

func (join *JoinStage) serialiazeSign() []byte {
	bytes := []byte{0, IReact}
	util.PutUint64(join.EpochStamp, &bytes)
	util.PutToken(join.Author, &bytes)
	util.PutToken(join.Stage, &bytes)
	util.PutToken(join.DiffHellKey, &bytes)
	util.PutString(join.Presentation, &bytes)
	util.PutToken(join.Attorney, &bytes)
	return bytes
}

func (join *JoinStage) serializeWalletSign() []byte {
	bytes := join.serialiazeSign()
	util.PutSignature(join.Signature, &bytes)
	util.PutToken(join.Wallet, &bytes)
	util.PutUint64(join.Fee, &bytes)
	return bytes
}

func ParseJoinStage(data []byte) *JoinStage {
	var position int
	if data[0] != 0 || data[1] != IJoinStage {
		return nil
	}
	join := JoinStage{}
	join.EpochStamp, join.Author, position = parseHeader(data)
	join.Stage, position = util.ParseToken(data, position)
	join.DiffHellKey, position = util.ParseToken(data, position)
	join.Presentation, position = util.ParseString(data, position)
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

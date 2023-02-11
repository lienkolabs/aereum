package instructions

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/util"
)

type Withdraw struct {
	EpochStamp uint64
	Token      crypto.Token
	Value      uint64
	Fee        uint64
	Signature  crypto.Signature
}

func (w *Withdraw) serializeSign() []byte {
	bytes := []byte{0, IWithdraw}
	util.PutUint64(w.EpochStamp, &bytes)
	util.PutToken(w.Token, &bytes)
	util.PutUint64(w.Value, &bytes)
	util.PutUint64(w.Fee, &bytes)
	return bytes
}

func (w *Withdraw) Serialize() []byte {
	bytes := w.serializeSign()
	util.PutSignature(w.Signature, &bytes)
	return bytes
}

func (w *Withdraw) Authority() crypto.Token {
	return crypto.ZeroToken
}

func (w *Withdraw) Epoch() uint64 {
	return w.EpochStamp
}

func (w *Withdraw) Kind() byte {
	return IWithdraw
}

func (w *Withdraw) Payments() *Payment {
	return NewPayment(crypto.HashToken(w.Token), w.Fee)
}

func (w *Withdraw) Validate(v InstructionValidator) bool {
	payments := w.Payments()
	if v.CanPay(payments) && v.CanWithdraw(crypto.HashToken(w.Token), w.Value) {
		v.AddFeeCollected(w.Fee)
		return true
	}
	return false
}

func (w *Withdraw) Sign(key crypto.PrivateKey) {
	bytes := w.serializeSign()
	w.Signature = key.Sign(bytes)
}

func (w *Withdraw) JSON() string {
	bulk := &util.JSONBuilder{}
	bulk.PutUint64("version", 0)
	bulk.PutUint64("instructionType", uint64(IWithdraw))
	bulk.PutUint64("epoch", w.EpochStamp)
	bulk.PutHex("token", w.Token[:])
	bulk.PutUint64("value", w.Value)
	bulk.PutUint64("fee", w.Fee)
	bulk.PutBase64("signature", w.Signature[:])
	return bulk.ToString()
}

func ParseWithdraw(data []byte) *Withdraw {
	if len(data) < 2 || data[1] != IWithdraw {
		return nil
	}
	p := Withdraw{}
	position := 2
	p.EpochStamp, position = util.ParseUint64(data, position)
	p.Token, position = util.ParseToken(data, position)
	p.Value, position = util.ParseUint64(data, position)
	p.Fee, position = util.ParseUint64(data, position)
	msgToVerify := data[0:position]
	p.Signature, _ = util.ParseSignature(data, position)
	if !p.Token.Verify(msgToVerify, p.Signature) {
		return nil
	}
	return &p
}

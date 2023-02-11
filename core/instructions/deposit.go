package instructions

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/util"
)

type Deposit struct {
	EpochStamp uint64
	Token      crypto.Token
	Value      uint64
	Fee        uint64
	Signature  crypto.Signature
}

func (d *Deposit) serializeSign() []byte {
	bytes := []byte{0, IDeposit}
	util.PutUint64(d.EpochStamp, &bytes)
	util.PutToken(d.Token, &bytes)
	util.PutUint64(d.Value, &bytes)
	util.PutUint64(d.Fee, &bytes)
	return bytes
}

func (d *Deposit) Serialize() []byte {
	bytes := d.serializeSign()
	util.PutSignature(d.Signature, &bytes)
	return bytes
}

func (d *Deposit) Authority() crypto.Token {
	return crypto.ZeroToken
}

func (d *Deposit) Epoch() uint64 {
	return d.EpochStamp
}

func (d *Deposit) Kind() byte {
	return IDeposit
}

func (d *Deposit) Payments() *Payment {
	return NewPayment(crypto.HashToken(d.Token), d.Value+d.Fee)
}

func (d *Deposit) Validate(v InstructionValidator) bool {
	payments := d.Payments()
	if v.CanPay(payments) {
		v.AddFeeCollected(d.Fee)
		v.Deposit(crypto.HashToken(d.Token), d.Value)
		return true
	}
	return false
}

func (d *Deposit) Sign(key crypto.PrivateKey) {
	bytes := d.serializeSign()
	d.Signature = key.Sign(bytes)
}

func (d *Deposit) JSON() string {
	bulk := &util.JSONBuilder{}
	bulk.PutUint64("version", 0)
	bulk.PutUint64("instructionType", uint64(IDeposit))
	bulk.PutUint64("epoch", d.EpochStamp)
	bulk.PutHex("token", d.Token[:])
	bulk.PutUint64("value", d.Value)
	bulk.PutUint64("fee", d.Fee)
	bulk.PutBase64("signature", d.Signature[:])
	return bulk.ToString()
}

func ParseDeposit(data []byte) *Deposit {
	if len(data) < 2 || data[1] != IDeposit {
		return nil
	}
	p := Deposit{}
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

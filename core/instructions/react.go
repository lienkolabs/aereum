package instructions

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/util"
)

type React struct {
	EpochStamp      uint64
	Author          crypto.Token
	Hash            []byte
	Reaction        byte
	Attorney        crypto.Token
	Signature       crypto.Signature
	Wallet          crypto.Token
	Fee             uint64
	WalletSignature crypto.Signature
}

func (react *React) Kind() byte {
	return IContent
}

func (react *React) Authority() crypto.Token {
	return react.Author
}

func (react *React) Epoch() uint64 {
	return react.EpochStamp
}

func (react *React) Payments() *Payment {
	if react.Wallet != crypto.ZeroToken {
		return NewPayment(crypto.HashToken(react.Wallet), react.Fee)
	}
	if react.Attorney != crypto.ZeroToken {
		return NewPayment(crypto.HashToken(react.Wallet), react.Fee)
	}
	return NewPayment(crypto.HashToken(react.Author), react.Fee)
}

func (react *React) Validate(v InstructionValidator) bool {
	if v.HasMember(crypto.HashToken(react.Author)) && v.CanPay(react.Payments()) {
		v.AddFeeCollected(react.Fee)
		return true
	}
	return false
}

func (react *React) Serialize() []byte {
	bytes := react.serializeWalletSign()
	util.PutSignature(react.WalletSignature, &bytes)
	return bytes
}

func (react *React) Sign(key crypto.PrivateKey) {
	bytes := react.serialiaeSign()
	react.Signature = key.Sign(bytes)
}

func (react *React) AppendFee(wallet crypto.PrivateKey, fee uint64) {
	token := wallet.PublicKey()
	if token != react.Author {
		react.Wallet = token
	} else {
		react.Wallet = crypto.ZeroToken
	}
	react.Fee = fee
	bytes := react.serializeWalletSign()
	react.WalletSignature = wallet.Sign(bytes)
}

func (react *React) serialiaeSign() []byte {
	bytes := []byte{0, IReact}
	util.PutUint64(react.EpochStamp, &bytes)
	util.PutToken(react.Author, &bytes)
	util.PutByteArray(react.Hash, &bytes)
	util.PutByte(react.Reaction, &bytes)
	util.PutToken(react.Attorney, &bytes)
	return bytes
}

func (react *React) serializeWalletSign() []byte {
	bytes := react.serialiaeSign()
	util.PutSignature(react.Signature, &bytes)
	util.PutToken(react.Wallet, &bytes)
	util.PutUint64(react.Fee, &bytes)
	return bytes
}

func ParseReact(data []byte) *React {
	var position int
	if data[0] != 0 || data[1] != IReact {
		return nil
	}
	react := React{}
	react.EpochStamp, react.Author, position = parseHeader(data)
	react.Hash, position = util.ParseByteArray(data, position)
	react.Reaction, position = util.ParseByte(data, position)
	react.Attorney, position = util.ParseToken(data, position)
	msg := data[0:position]
	react.Signature, position = util.ParseSignature(data, position)
	if !checkSignature(msg, react.Signature, react.Attorney, react.Author) {
		return nil
	}

	react.Wallet, position = util.ParseToken(data, position)
	react.Fee, position = util.ParseUint64(data, position)
	msg = data[0:position]
	react.WalletSignature, position = util.ParseSignature(data, position)
	if !checkWalletSignature(msg, react.WalletSignature, react.Wallet, react.Attorney, react.Author) {
		return nil
	}
	if position != len(data) {
		return nil
	}
	return &react
}

func (react *React) JSON() string {
	bulk := genericJSON(IReact, react.EpochStamp, react.Fee, react.Author, react.Wallet, react.Attorney,
		react.Signature, react.WalletSignature)
	bulk.PutHex("hash", react.Hash)
	bulk.PutUint64("reaction", uint64(react.Reaction))
	return bulk.ToString()
}

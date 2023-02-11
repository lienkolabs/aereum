package instructions

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/util"
)

type AcceptJoinRequest struct {
	EpochStamp      uint64
	Author          crypto.Token
	Stage           crypto.Token
	Member          crypto.Token
	DiffieHelKey    crypto.Token
	Read            []byte
	Submit          []byte
	Moderate        []byte
	ModSignature    crypto.Signature
	Attorney        crypto.Token
	Signature       crypto.Signature
	Wallet          crypto.Token
	Fee             uint64
	WalletSignature crypto.Signature
}

func (accept *AcceptJoinRequest) Authority() crypto.Token {
	return accept.Author
}

func (accept *AcceptJoinRequest) Epoch() uint64 {
	return accept.EpochStamp
}

func (accept *AcceptJoinRequest) Kind() byte {
	return IAcceptJoinRequest
}

func (accept *AcceptJoinRequest) Payments() *Payment {
	if accept.Wallet != crypto.ZeroToken {
		return NewPayment(crypto.HashToken(accept.Wallet), accept.Fee)
	}
	if accept.Attorney != crypto.ZeroToken {
		return NewPayment(crypto.HashToken(accept.Wallet), accept.Fee)
	}
	return NewPayment(crypto.HashToken(accept.Author), accept.Fee)
}

func (accept *AcceptJoinRequest) Serialize() []byte {
	bytes := accept.serializeWalletSign()
	util.PutSignature(accept.WalletSignature, &bytes)
	return bytes
}

func (accept *AcceptJoinRequest) Validate(v InstructionValidator) bool {
	if !v.HasMember(crypto.HashToken(accept.Author)) {
		return false
	}
	audienceHash := crypto.HashToken(accept.Stage)
	keys := v.GetAudienceKeys(audienceHash)
	if keys == nil || keys.Moderate == crypto.ZeroToken {
		return false
	}
	if !keys.Moderate.Verify(accept.serialiazeModSign(), accept.ModSignature) {
		return false
	}
	if v.CanPay(accept.Payments()) {
		v.AddFeeCollected(accept.Fee)
		return true
	}
	return false
}

func (create *AcceptJoinRequest) JSON() string {
	bulk := genericJSON(IAcceptJoinRequest, create.EpochStamp, create.Fee, create.Author, create.Wallet, create.Attorney,
		create.Signature, create.WalletSignature)
	bulk.PutHex("stage", create.Stage[:])
	bulk.PutHex("member", create.Member[:])
	bulk.PutHex("diffieHellKey", create.DiffieHelKey[:])
	if create.Read != nil {
		bulk.PutHex("read", create.Read[:])
	}
	if create.Submit != nil {
		bulk.PutHex("submit", create.Read[:])
	}
	if create.Moderate != nil {
		bulk.PutHex("moderate", create.Read[:])
	}
	bulk.PutHex("modSignature", create.ModSignature[:])
	return bulk.ToString()
}

func (create *AcceptJoinRequest) serialiazeModSign() []byte {
	bytes := []byte{0, IReact}
	util.PutUint64(create.EpochStamp, &bytes)
	util.PutToken(create.Author, &bytes)
	util.PutToken(create.Stage, &bytes)
	util.PutToken(create.Member, &bytes)
	util.PutToken(create.DiffieHelKey, &bytes)
	util.PutByteArray(create.Read, &bytes)
	util.PutByteArray(create.Submit, &bytes)
	util.PutByteArray(create.Moderate, &bytes)
	return bytes
}

func (create *AcceptJoinRequest) serialiazeSign() []byte {
	bytes := create.serialiazeModSign()
	util.PutSignature(create.ModSignature, &bytes)
	util.PutToken(create.Attorney, &bytes)
	return bytes
}
func (create *AcceptJoinRequest) serializeWalletSign() []byte {
	bytes := create.serialiazeSign()
	util.PutSignature(create.Signature, &bytes)
	util.PutToken(create.Wallet, &bytes)
	util.PutUint64(create.Fee, &bytes)
	return bytes
}

func ParseAcceptJoinRequest(data []byte) *AcceptJoinRequest {
	var position int
	if data[0] != 0 || data[1] != IAcceptJoinRequest {
		return nil
	}
	accept := AcceptJoinRequest{}
	accept.EpochStamp, accept.Author, position = parseHeader(data)
	accept.Stage, position = util.ParseToken(data, position)
	accept.Member, position = util.ParseToken(data, position)
	accept.DiffieHelKey, position = util.ParseToken(data, position)
	accept.Read, position = util.ParseByteArray(data, position)
	accept.Submit, position = util.ParseByteArray(data, position)
	accept.Moderate, position = util.ParseByteArray(data, position)
	accept.ModSignature, position = util.ParseSignature(data, position)
	accept.Attorney, position = util.ParseToken(data, position)
	msg := data[0:position]
	accept.Signature, position = util.ParseSignature(data, position)
	if !checkSignature(msg, accept.Signature, accept.Attorney, accept.Author) {
		return nil
	}
	accept.Wallet, position = util.ParseToken(data, position)
	accept.Fee, position = util.ParseUint64(data, position)
	msg = data[0:position]
	accept.WalletSignature, position = util.ParseSignature(data, position)
	if !checkWalletSignature(msg, accept.WalletSignature, accept.Wallet, accept.Attorney, accept.Author) {
		return nil
	}
	if position != len(data) {
		return nil
	}
	return &accept
}

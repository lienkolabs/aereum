package instructions

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/util"
)

// Content is the primitive digital interaction within aereum protocol.
// Any content is published on a Stage. It can be either naked or encrypted
// accordiing to a cipher defined by the stage. Stages can be moderated,
// in which case only authors with submission right can publish content.
// content lifecycle etc etc etc
type Content struct {
	EpochStamp      uint64
	Published       uint64
	Author          crypto.Token
	Stage           crypto.Token
	ContentType     string
	Content         []byte
	Hash            []byte
	Sponsored       bool
	Encrypted       bool
	SubSignature    crypto.Signature
	Moderator       crypto.Token
	ModSignature    crypto.Signature
	Attorney        crypto.Token
	Signature       crypto.Signature
	Wallet          crypto.Token
	Fee             uint64
	WalletSignature crypto.Signature
}

// Binary encoding
func (content *Content) Serialize() []byte {
	bytes := content.serializeWalletBulk()
	util.PutSignature(content.WalletSignature, &bytes)
	return bytes
}

func (content *Content) Kind() byte {
	return IContent
}

func (a *Content) Payments() *Payment {
	if len(a.Wallet) > 0 {
		return NewPayment(crypto.HashToken(a.Wallet), a.Fee)
	}
	if len(a.Attorney) > 0 {
		return NewPayment(crypto.HashToken(a.Attorney), a.Fee)
	}
	return NewPayment(crypto.HashToken(a.Author), a.Fee)
}

func (a *Content) Authority() crypto.Token {
	if a.Moderator != crypto.ZeroToken {
		return a.Moderator
	}
	return a.Author
}

func (a *Content) Epoch() uint64 {
	return a.EpochStamp
}

func (content *Content) Validate(v InstructionValidator) bool {
	if content.EpochStamp > v.Epoch() {
		return false
	}
	if !v.HasMember(crypto.HashToken(content.Author)) {
		return false
	}
	stageHash := crypto.HashToken(content.Stage)
	stageKeys := v.GetAudienceKeys(stageHash)
	if stageKeys == nil {
		return false
	}
	payments := content.Payments()
	if content.Sponsored {
		if content.Encrypted {
			return false
		}
		if len(content.SubSignature) != 0 || len(content.ModSignature) != 0 {
			return false
		}
		hash := crypto.Hasher(append(content.Author[:], content.Stage[:]...))
		ok, contentHash := v.HasGrantedSponser(hash)
		if !ok {
			return false
		}
		if !crypto.Hasher(content.Content).Equal(contentHash) {
			return false
		}
		if v.SetPublishSponsor(hash) && v.CanPay(payments) {
			v.AddFeeCollected(content.Fee)
			return true
		}
		return false
	}
	if !stageKeys.Submit.Verify(content.serializeSubBulk()[10:], content.SubSignature) {
		return false
	}
	if content.Moderator != crypto.ZeroToken {
		if !stageKeys.Moderate.Verify(content.serializeModBulk(), content.ModSignature) {
			return false
		}
	}
	if v.CanPay(payments) {
		v.AddFeeCollected(content.Fee)
		return true
	}
	return false
}

func (content *Content) JSON() string {
	bulk := &util.JSONBuilder{}
	bulk.PutUint64("version", 0)
	bulk.PutUint64("instructionType", uint64(IContent))
	bulk.PutUint64("epoch", content.EpochStamp)
	bulk.PutUint64("published", content.Published)
	bulk.PutHex("author", content.Author[:])
	bulk.PutHex("audience", content.Stage[:])
	bulk.PutString("contentType", content.ContentType)
	bulk.PutBase64("content", content.Content)
	bulk.PutHex("hash", content.Hash)
	if content.Wallet != crypto.ZeroToken {
		bulk.PutHex("wallet", content.Wallet[:])
	}
	bulk.PutUint64("fee", content.Fee)
	if content.Attorney != crypto.ZeroToken {
		bulk.PutHex("attorney", content.Attorney[:])
	}
	bulk.PutBase64("signature", content.Signature[:])
	bulk.PutBase64("walletSignature", content.WalletSignature[:])
	return bulk.ToString()
}

func (content *Content) SubmitSign(key crypto.PrivateKey) {
	data := content.serializeSubBulk()
	// ignore EpochStamp on subsignature
	content.Signature = key.Sign(data[10:])
}

func (content *Content) ModerateSign(key crypto.PrivateKey) {
	data := content.serializeModBulk()
	content.ModSignature = key.Sign(data)
}

func (content *Content) Sign(key crypto.PrivateKey, attorney crypto.Token) {
	content.Attorney = attorney
	data := content.serializeSignBulk()
	content.Signature = key.Sign(data)
}

func (content *Content) AppendFee(fee uint64, wallet crypto.PrivateKey) {
	content.Wallet = wallet.PublicKey()
	content.Fee = fee
	data := content.serializeWalletBulk()
	content.WalletSignature = wallet.Sign(data)
}

// partial serialization up to the Encrypted field
func (content *Content) serializeSubBulk() []byte {
	bytes := []byte{0, IContent}
	util.PutUint64(content.EpochStamp, &bytes)
	util.PutUint64(content.Published, &bytes)
	util.PutToken(content.Author, &bytes)
	util.PutToken(content.Stage, &bytes)
	util.PutString(content.ContentType, &bytes)
	util.PutByteArray(content.Content, &bytes)
	util.PutByteArray(content.Hash, &bytes)
	util.PutBool(content.Sponsored, &bytes)
	util.PutBool(content.Encrypted, &bytes)
	return bytes
}

// partial serialization up to Moderator field
func (content *Content) serializeModBulk() []byte {
	bytes := content.serializeSubBulk()
	util.PutSignature(content.SubSignature, &bytes)
	util.PutToken(content.Moderator, &bytes)
	return bytes
}

// partial serialization up to Attorney field
func (content *Content) serializeSignBulk() []byte {
	bytes := content.serializeModBulk()
	util.PutSignature(content.ModSignature, &bytes)
	util.PutToken(content.Attorney, &bytes)
	return bytes
}

// partial serialization up to Fee field
func (content *Content) serializeWalletBulk() []byte {
	bytes := content.serializeSignBulk()
	util.PutSignature(content.Signature, &bytes)
	util.PutToken(content.Wallet, &bytes)
	util.PutUint64(content.Fee, &bytes)
	return bytes
}

func ParseContent(data []byte) *Content {
	if data[0] != 0 || data[1] != IContent {
		return nil
	}
	var content Content
	position := 2
	content.EpochStamp, position = util.ParseUint64(data, position)
	content.Published, position = util.ParseUint64(data, position)
	content.Author, position = util.ParseToken(data, position)
	content.Stage, position = util.ParseToken(data, position)
	content.ContentType, position = util.ParseString(data, position)
	content.Content, position = util.ParseByteArray(data, position)
	content.Hash, position = util.ParseByteArray(data, position)
	content.Sponsored, position = util.ParseBool(data, position)
	content.Encrypted, position = util.ParseBool(data, position)
	content.SubSignature, position = util.ParseSignature(data, position)
	content.Moderator, position = util.ParseToken(data, position)
	content.ModSignature, position = util.ParseSignature(data, position)
	if len(content.Moderator) == 0 && (content.EpochStamp != content.Published) {
		return nil
	}
	content.Attorney, position = util.ParseToken(data, position)
	msg := data[0:position]
	token := content.Author
	if len(content.Attorney) > 0 {
		token = content.Attorney
	} else if len(content.Moderator) > 0 {
		token = content.Moderator
	}
	content.Signature, position = util.ParseSignature(data, position)
	if !token.Verify(msg, content.Signature) {
		return nil
	}
	content.Wallet, position = util.ParseToken(data, position)
	content.Fee, position = util.ParseUint64(data, position)
	msg = data[0:position]
	content.WalletSignature, _ = util.ParseSignature(data, position)
	if content.Wallet != crypto.ZeroToken {
		token = content.Wallet
	}
	if !token.Verify(msg, content.WalletSignature) {
		return nil
	}
	return &content
}

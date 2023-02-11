package instructions

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/util"
)

func checkWalletSignature(bytes []byte, signature crypto.Signature, wallet, attorney, author crypto.Token) bool {
	if wallet != crypto.ZeroToken {
		return wallet.Verify(bytes, signature)
	}
	if attorney != crypto.ZeroToken {
		return attorney.Verify(bytes, signature)
	}

	return author.Verify(bytes, signature)
}

func checkSignature(bytes []byte, signature crypto.Signature, attorney, author crypto.Token) bool {
	if attorney != crypto.ZeroToken {
		return attorney.Verify(bytes, signature)
	}
	return author.Verify(bytes, signature)
}

func parseHeader(data []byte) (uint64, crypto.Token, int) {
	position := 2
	epoch, position := util.ParseUint64(data, position)
	author, position := util.ParseToken(data, position)
	return epoch, author, position
}

func genericJSON(kind byte, epoch, fee uint64, author, wallet, attorney crypto.Token,
	signature, walletSignature crypto.Signature) *util.JSONBuilder {
	b := &util.JSONBuilder{}
	b.PutUint64("version", 0)
	b.PutUint64("instructionType", uint64(kind))
	b.PutUint64("epoch", epoch)
	b.PutHex("author", author[:])
	if wallet != crypto.ZeroToken {
		b.PutHex("wallet", wallet[:])
	}
	b.PutUint64("fee", fee)
	if attorney != crypto.ZeroToken {
		b.PutHex("attorney", attorney[:])
	}
	b.PutBase64("signature", signature[:])
	b.PutBase64("walletSignature", walletSignature[:])
	return b
}

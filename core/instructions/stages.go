package instructions

import "github.com/lienkolabs/aereum/core/crypto"

type StageKeys struct {
	Moderate crypto.Token
	Submit   crypto.Token
	Stage    crypto.Token
	Flag     byte
}

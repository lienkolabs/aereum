package edge

import (
	"errors"

	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/crypto/dh"
	"github.com/lienkolabs/aereum/core/instructions"
)

const (
	PUBLISH   = 1
	MODERATE  = 2
	ENCRYPTED = 1
	CLOSED    = 1 << 1
	MODERATED = 1 << 2
)

var InsufficientKnowledgeError = errors.New("user does not have knowledge to perform action")

type Author struct {
	Author    crypto.Token
	Attorney  crypto.Token
	Signer    crypto.PrivateKey
	Wallet    crypto.PrivateKey
	Stages    map[crypto.Token]*Stage
	Secrets   *SecureVault
	Ephemeral map[crypto.Token]crypto.Token
	Realay    Realay
	Gateway   Gateway
}

// Unencrypted Content
type Content struct {
	ContentType string
	Content     []byte
}

// Stage keep information about stages.
// Readers, Submitors, Moderators fields maps member tokens into their self-provided
// Diffie Hellman ephemeral keys. They must be used to update Stage permissions or
// rotate its keys. All available privatye keys should be stored on Authors SecureVault
type Stage struct {
	Token       crypto.Token
	Flag        byte
	Description string
	Public      bool
	Submission  crypto.Token
	Moderation  crypto.Token
	Readers     map[crypto.Token]crypto.Token
	Submitors   map[crypto.Token]crypto.Token
	Moderators  map[crypto.Token]crypto.Token
	Content     []Content
	Live        bool
}

type DateAndSigner interface {
	SetEpoch(uint64)
	Sign(key crypto.PrivateKey)
}

func (a *Author) CreateStage(description string, permissions, flag byte) (*instructions.CreateStage, error) {
	owner, err := a.Secrets.NewKey()
	if err != nil {
		return nil, err
	}
	secrets := StageSecrets{
		Ownership: owner,
	}
	stage := instructions.CreateStage{
		Author:      a.Author,
		Stage:       owner.PublicKey(),
		Description: description,
		Flag:        flag,
		Attorney:    a.Attorney,
	}
	if (permissions & ENCRYPTED) == 1 {
		secrets.Cipher = crypto.NewCipherKey()
	}
	if (permissions & CLOSED) == 1 {
		stage.Submission, secrets.Submission = crypto.RandomAsymetricKey()
	}
	if (permissions & MODERATED) == 1 {
		stage.Moderation, secrets.Submission = crypto.RandomAsymetricKey()
	}
	return &stage, nil
}

func (a *Author) JoinStage(stage crypto.Token, introduction string) (*instructions.JoinStage, crypto.PrivateKey) {
	dhPrv, dhPub := dh.NewEphemeralKey()
	join := instructions.JoinStage{
		Author:       a.Author,
		Stage:        stage,
		DiffHellKey:  dhPub,
		Presentation: introduction,
		Attorney:     a.Attorney,
	}
	return &join, dhPrv
}

func (a *Author) AcceptJoinRequest(request *instructions.JoinStage, permissions byte) (*instructions.AcceptJoinRequest, error) {
	stage, ok := a.Stages[request.Stage]
	if !ok {
		return nil, InsufficientKnowledgeError
	}
	moderation, ok := a.Secrets.GetKey(stage.Moderation)
	if !ok {
		return nil, InsufficientKnowledgeError
	}
	prv, pub := dh.NewEphemeralKey()
	accept := instructions.AcceptJoinRequest{
		Author:       a.Author,
		Stage:        request.Stage,
		Member:       request.Author,
		DiffieHelKey: pub,
	}
	cipher := dh.ConsensusCipher(prv, request.DiffHellKey)
	if !stage.Public {
		stageCipherKey, ok := a.Secrets.GetCipher(request.Stage)
		if !ok {
			return nil, InsufficientKnowledgeError
		}
		accept.Read = cipher.Seal(stageCipherKey)
	}
	if (stage.Submission != crypto.ZeroToken) && (permissions >= PUBLISH) {
		subKey, ok := a.Secrets.GetKey(stage.Submission)
		if !ok {
			return nil, InsufficientKnowledgeError
		}
		accept.Submit = cipher.Seal(subKey[:])
	}
	if (stage.Moderation != crypto.ZeroToken) && (permissions >= MODERATE) {
		modKey, ok := a.Secrets.GetKey(stage.Moderation)
		if !ok {
			return nil, InsufficientKnowledgeError
		}
		accept.Moderate = cipher.Seal(modKey[:])
	}
	return nil
}

func (a *Author) IncorporateStage(accept *instructions.AcceptJoinRequest) {
	cipher := dh.ConsensusCipher()
}

func (a *Author) UpdateStage(description string, flag byte, updatekeys bool) *instructions.UpdateStage {
	return nil
}

func (a *Author) Content(contentType string, content []byte, ciphered bool) *instructions.Content {
	return nil
}

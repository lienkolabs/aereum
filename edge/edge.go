package edge

import (
	"errors"
	"io"

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

var (
	InsufficientKnowledgeError = errors.New("user does not have knowledge to perform action")
	StageNotFoundError         = errors.New("stage not found")
)

type Author struct {
	Author    crypto.Token
	Attorney  crypto.Token
	Signer    crypto.PrivateKey
	Stages    map[crypto.Token]*Stage
	Secrets   *SecureVault
	Ephemeral map[crypto.Token]crypto.Token
	Realay    Realay
	Gateway   Gateway
}

// Unencrypted Content
type Content struct {
	Author      crypto.Token
	Stage       crypto.Token
	Sponsored   bool
	Encrypted   bool
	ContentType string
	Content     []byte
}

type NullWriterCloser struct{}

func (n NullWriterCloser) Write(b []byte) (int, error) {
	return len(b), nil
}

func (n NullWriterCloser) Close() error {
	return nil
}

func NewContentMemoryStore(cache int) *ContentStore {
	return &ContentStore{
		io:        NullWriterCloser{},
		content:   make([]Content, 0),
		cacheSize: cache,
	}
}

func OpenContentDiskStore(cache int, filePath string) (*ContentStore, error) {
	return nil, nil
}

func NewContentDiskStore(cache int, filePath string) (*ContentStore, error) {
	return nil, nil
}

type ContentStore struct {
	io        io.WriteCloser
	content   []Content
	cacheSize int
}

func (c *ContentStore) AppendContent(content *instructions.Content) error {
	newContent := Content{
		Encrypted:   content.Encrypted,
		Sponsored:   content.Sponsored,
		ContentType: content.ContentType,
		Content:     content.Content,
	}
	if len(c.content) < c.cacheSize {
		c.content = append(c.content, newContent)
	} else {
		c.content = append(c.content[:len(c.content)-1], newContent)
	}
	bytes := content.Serialize()
	if n, err := c.io.Write(bytes); n != len(bytes) {
		return err
	}
	return nil
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
	Submission  TokenHistory
	Moderation  TokenHistory
	Content     *ContentStore
	Members     *StageMembers
	Live        bool
}

type StageMembers struct {
	Readers    map[crypto.Token]crypto.Token
	Submitors  map[crypto.Token]crypto.Token
	Moderators map[crypto.Token]crypto.Token
}

type DateAndSigner interface {
	SetEpoch(uint64)
	Sign(key crypto.PrivateKey)
}

// TokenHistory is a reverse history of tokens. The first token is from an epoch
// after the second token and so on.
type TokenHistory []EpochToken

func (t TokenHistory) Append(epoch uint64, token crypto.Token) {
	for n, epochToken := range t {
		if epochToken.Epoch < epoch {
			return epochToken.Token, true
		}
	}

}

func (t TokenHistory) Token(epoch uint64) (crypto.Token, bool) {
	for _, epochToken := range t {
		if epochToken.Epoch < epoch {
			return epochToken.Token, true
		}
	}
	return crypto.ZeroToken, false
}

type EpochToken struct {
	Epoch uint64
	Token crypto.Token
}

type Drama struct {
	Stages    map[crypto.Token]*Stage
	ContentIO io.WriteCloser
	StagesIO  io.WriteCloser
}

func (d Drama) AppendContent(content instructions.Content) {

}

func (d Drama) IncorporateContent()

func (a *Author) CreateStage(description string, permissions, flag byte) (*instructions.CreateStage, error) {
	owner, err := a.Secrets.NewKey()
	if err != nil {
		return nil, err
	}
	stage := Stage{
		Token:       owner.PublicKey(),
		Flag:        flag,
		Description: description,
		Readers:     make(map[crypto.Token]crypto.Token),
		Submitors:   make(map[crypto.Token]crypto.Token),
		Moderators:  make(map[crypto.Token]crypto.Token),
		Content:     make([]Content, 0),
		Live:        false,
	}
	create := instructions.CreateStage{
		Author:      a.Author,
		Stage:       owner.PublicKey(),
		Description: description,
		Flag:        flag,
		Attorney:    a.Attorney,
	}
	if (permissions & ENCRYPTED) == 1 {
		if stage.CipherKey, err = a.Secrets.NewCipherKey(); err != nil {
			return nil, err
		}
	}
	if (permissions & CLOSED) == 1 {
		if prvKey, err := a.Secrets.NewKey(); err != nil {

			return nil, err
		} else {
			stage.Submission = prvKey.PublicKey()
			create.Submission = stage.Submission
		}
	}
	if (permissions & MODERATED) == 1 {
		if prvKey, err := a.Secrets.NewKey(); err != nil {
			return nil, err
		} else {
			stage.Moderation = prvKey.PublicKey()
			create.Moderation = stage.Moderation
		}
	}
	return &create, nil
}

func (a *Author) StageCreated(create *instructions.CreateStage) error {
	stage, ok := a.Stages[create.Stage]
	if !ok {
		return StageNotFoundError
	}
	stage.Live = true
	return nil
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

package state

import (
	"github.com/lienkolabs/aereum/core/crypto"
)

type State struct {
	Epoch           uint64
	Members         *hashVault
	Captions        *hashVault
	Wallets         *Wallet
	Deposits        *Wallet
	Stages          *Stage
	SponsorOffers   *HashUint64Vault
	SponsorGranted  *Sponsor
	PowerOfAttorney *hashVault
	EphemeralTokens *HashUint64Vault
	SponsorExpire   map[uint64]crypto.Hash
	EphemeralExpire map[uint64]crypto.Hash
}

func NewGenesisState() (*State, crypto.PrivateKey) {
	pubKey, prvKey := crypto.RandomAsymetricKey()
	state := State{
		Epoch:           0,
		Members:         NewHashVault("members", 0, 8),
		Captions:        NewHashVault("captions", 0, 8),
		Wallets:         NewMemoryWalletStore(0, 8),
		Deposits:        NewMemoryWalletStore(0, 8),
		Stages:          NewMemoryAudienceStore(0, 8),
		SponsorOffers:   NewExpireHashVault("sponsoroffer", 0, 8),
		SponsorGranted:  NewSponsorShipOfferStore(0, 8),
		PowerOfAttorney: NewHashVault("poa", 0, 8),
		EphemeralTokens: NewExpireHashVault("ephemeral", 0, 8),
		SponsorExpire:   make(map[uint64]crypto.Hash),
		EphemeralExpire: make(map[uint64]crypto.Hash),
	}
	state.Members.InsertToken(pubKey)
	state.Captions.InsertHash(crypto.Hasher([]byte("Aereum Network Genesis")))
	state.Wallets.Credit(pubKey, 1e6)
	return &state, prvKey
}

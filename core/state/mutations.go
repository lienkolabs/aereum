package state

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/instructions"
)

type Mutation struct {
	DeltaWallets  map[crypto.Hash]int
	DeltaDeposits map[crypto.Hash]int
	GrantPower    map[crypto.Hash]struct{}
	RevokePower   map[crypto.Hash]struct{}
	UseSpnOffer   map[crypto.Hash]struct{}
	GrantSponsor  map[crypto.Hash]crypto.Hash // hash of sponsor token + audience -> content hash
	PublishSpn    map[crypto.Hash]struct{}
	NewSpnOffer   map[crypto.Hash]uint64
	NewMembers    map[crypto.Hash]struct{}
	NewCaption    map[crypto.Hash]struct{}
	NewStages     map[crypto.Hash]instructions.StageKeys
	StageUpdate   map[crypto.Hash]instructions.StageKeys
	NewEphemeral  map[crypto.Hash]uint64
}

func NewMutation() *Mutation {
	return &Mutation{
		DeltaWallets: make(map[crypto.Hash]int),
		GrantPower:   make(map[crypto.Hash]struct{}),
		RevokePower:  make(map[crypto.Hash]struct{}),
		UseSpnOffer:  make(map[crypto.Hash]struct{}),
		GrantSponsor: make(map[crypto.Hash]crypto.Hash),
		PublishSpn:   make(map[crypto.Hash]struct{}),
		NewSpnOffer:  make(map[crypto.Hash]uint64),
		NewMembers:   make(map[crypto.Hash]struct{}),
		NewCaption:   make(map[crypto.Hash]struct{}),
		NewStages:    make(map[crypto.Hash]instructions.StageKeys),
		StageUpdate:  make(map[crypto.Hash]instructions.StageKeys),
		NewEphemeral: make(map[crypto.Hash]uint64),
	}
}

func (m *Mutation) DeltaBalance(hash crypto.Hash) int {
	balance := m.DeltaWallets[hash]
	return balance
}

func (m *Mutation) HasGrantedSponsorship(hash crypto.Hash) (bool, crypto.Hash) {
	if _, ok := m.PublishSpn[hash]; ok {
		return false, crypto.Hasher([]byte{})
	}
	contentHash, ok := m.GrantSponsor[hash]
	return ok, contentHash
}

func (m *Mutation) HasGrantPower(hash crypto.Hash) bool {
	_, ok := m.GrantPower[hash]
	return ok
}

func (m *Mutation) HasRevokePower(hash crypto.Hash) bool {
	_, ok := m.RevokePower[hash]
	return ok
}

func (m *Mutation) HasUsedSponsorOffer(hash crypto.Hash) bool {
	_, ok := m.UseSpnOffer[hash]
	return ok
}

func (m *Mutation) GetSponsorOffer(hash crypto.Hash) bool {
	_, ok := m.NewSpnOffer[hash]
	return ok
}

func (m *Mutation) HasMember(hash crypto.Hash) bool {
	_, ok := m.NewMembers[hash]
	return ok
}

func (m *Mutation) HasCaption(hash crypto.Hash) bool {
	_, ok := m.NewCaption[hash]
	return ok
}

func (m *Mutation) GetStage(hash crypto.Hash) *instructions.StageKeys {
	if audience, ok := m.StageUpdate[hash]; ok {
		return &audience
	}
	audience := m.NewStages[hash]
	return &audience
}

func (m *Mutation) HasEphemeral(hash crypto.Hash) (bool, uint64) {
	expire, ok := m.NewEphemeral[hash]
	return ok, expire
}

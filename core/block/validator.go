package block

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/instructions"
	"github.com/lienkolabs/aereum/core/state"
)

type MutatingState struct {
	State     *state.State
	Mutations *state.Mutation
}

// Balance returns the balance of fungible tokens associated to the hash.
// It returns zero if the hash is not found.
func (c *MutatingState) balance(hash crypto.Hash) uint64 {
	_, balance := c.State.Wallets.BalanceHash(hash)
	if c.Mutations == nil {
		return balance
	}
	delta := c.Mutations.DeltaBalance(hash)
	if delta < 0 {
		balance = balance - uint64(-delta)
	} else {
		balance = balance + uint64(delta)
	}
	return balance
}

// PowerOfAttorney checks if an attorney can sign on behalf of an author.
func (c *MutatingState) powerOfAttorney(hash crypto.Hash) bool {
	if c.Mutations != nil {
		if c.Mutations.HasRevokePower(hash) {
			return false
		}
		if c.Mutations.HasGrantPower(hash) {
			return true
		}
	}
	return c.State.PowerOfAttorney.ExistsHash(hash)
}

// SponsorshipOffer returns the expire epoch of an SponsorshipOffer. It returns
// zero if no offer is found of the given hash
func (c *MutatingState) sponsorshipOffer(hash crypto.Hash) uint64 {
	if c.Mutations != nil {
		if c.Mutations.HasUsedSponsorOffer(hash) {
			return 0
		}
		if offer := c.Mutations.GetSponsorOffer(hash); !offer {
			return 0
		}
	}
	expire := c.State.SponsorOffers.Exists(hash)
	return expire
}

// HasMeber returns the existance of a member.
func (c *MutatingState) hasMember(hash crypto.Hash) bool {
	if c.Mutations != nil && c.Mutations.HasMember(hash) {
		return true
	}
	return c.State.Members.ExistsHash(hash)
}

// HasGrantedSponsor returns the existence and the hash of the grantee +
// audience.
func (c *MutatingState) hasGrantedSponser(hash crypto.Hash) (bool, crypto.Hash) {
	if c.Mutations != nil {
		if ok, contentHash := c.Mutations.HasGrantedSponsorship(hash); ok {
			return true, contentHash
		}
	}
	ok, contentHash := c.State.SponsorGranted.GetContentHash(hash)
	return ok, crypto.Hasher(contentHash)
}

// HasCaption returns the existence of the caption
func (c *MutatingState) hasCaption(hash crypto.Hash) bool {
	if c.Mutations != nil && c.Mutations.HasCaption(hash) {
		return true
	}
	return c.State.Captions.ExistsHash(hash)
}

// GetAudienceKeys returns the audience keys
func (c *MutatingState) getAudienceKeys(hash crypto.Hash) *instructions.StageKeys {
	if c.Mutations != nil {
		if audience := c.Mutations.GetStage(hash); audience != nil {
			return audience
		}
	}
	keys := c.State.Stages.GetKeys(hash)
	return keys
}

// GetEphemeralExpire returns the expire epoch of the associated ephemeral token
// It returns zero if the token is not found.
func (c *MutatingState) getEphemeralExpire(hash crypto.Hash) (bool, uint64) {
	if c.Mutations != nil {
		if ok, expire := c.Mutations.HasEphemeral(hash); ok {
			return true, expire
		}
	}
	expire := c.State.EphemeralTokens.Exists(hash)
	return expire > 0, expire
}

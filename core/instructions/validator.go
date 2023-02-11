package instructions

import (
	"github.com/lienkolabs/aereum/core/crypto"
)

// InstructionValidotors offers the interface of the prevailing state of the
// aereum blockchain at a certain epoch together with functionality to alter
// that state accordingly to new instructions.
// It is necessary because we like to keep blockchain formation code on another
// namespace and the impossibility of circular reference of go packages forces
// us to introduce this interface within instructions package.
type InstructionValidator interface {
	SetNewGrantPower(hash crypto.Hash) bool
	SetNewRevokePower(hash crypto.Hash) bool
	SetNewUseSpnOffer(hash crypto.Hash) bool
	SetNewSpnOffer(hash crypto.Hash, expire uint64) bool
	SetPublishSponsor(hash crypto.Hash) bool
	SetNewEphemeralToken(hash crypto.Hash, expire uint64) bool
	SetNewMember(tokenHash crypto.Hash, captionHashe crypto.Hash) bool
	SetNewAudience(hash crypto.Hash, stage StageKeys) bool
	UpdateAudience(hash crypto.Hash, stage StageKeys) bool
	//Balance(hash crypto.Hash) uint64
	PowerOfAttorney(hash crypto.Hash) bool
	SponsorshipOffer(hash crypto.Hash) uint64
	HasMember(hash crypto.Hash) bool
	HasCaption(hash crypto.Hash) bool
	HasGrantedSponser(hash crypto.Hash) (bool, crypto.Hash)
	GetAudienceKeys(hash crypto.Hash) *StageKeys
	GetEphemeralExpire(hash crypto.Hash) (bool, uint64)
	AddFeeCollected(uint64)
	Epoch() uint64
	CanPay(payments *Payment) bool
	Deposit(hash crypto.Hash, value uint64)
	CanWithdraw(hash crypto.Hash, value uint64) bool
}

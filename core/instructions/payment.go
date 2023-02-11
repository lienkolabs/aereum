package instructions

import "github.com/lienkolabs/aereum/core/crypto"

type Wallet struct {
	Account        crypto.Hash
	FungibleTokens uint64
}

type Payment struct {
	Debit  []Wallet
	Credit []Wallet
}

func NewPayment(debitAcc crypto.Hash, value uint64) *Payment {
	return &Payment{
		Debit:  []Wallet{{debitAcc, value}},
		Credit: []Wallet{},
	}
}

func (p *Payment) NewCredit(account crypto.Hash, value uint64) {
	for _, credit := range p.Credit {
		if credit.Account.Equal(account) {
			credit.FungibleTokens += value
			return
		}
	}
	p.Credit = append(p.Credit, Wallet{Account: account, FungibleTokens: value})
}

func (p *Payment) NewDebit(account crypto.Hash, value uint64) {
	for _, debit := range p.Debit {
		if debit.Account.Equal(account) {
			debit.FungibleTokens += value
			return
		}
	}
	p.Debit = append(p.Debit, Wallet{Account: account, FungibleTokens: value})
}

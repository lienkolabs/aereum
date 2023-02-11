package instructions

import (
	"reflect"
	"testing"

	"github.com/lienkolabs/aereum/core/crypto"
)

func TestReactAuthor(t *testing.T) {
	_, author := crypto.RandomAsymetricKey()
	var react React
	react.EpochStamp = 317467328642
	react.Author = author.PublicKey()
	react.Hash = []byte{1, 2, 3, 4, 5, 8}
	react.Reaction = 10
	react.Sign(author)
	react.AppendFee(author, 7836548723687436)

	bytes := react.Serialize()
	react2 := ParseReact(bytes)

	if react2 == nil || !reflect.DeepEqual(react, *react2) {
		t.Error("React parsing or searializing is broken without wallet and attorney")
	}
}

func TestReactAttorney(t *testing.T) {
	_, author := crypto.RandomAsymetricKey()
	_, attorney := crypto.RandomAsymetricKey()
	var react React
	react.EpochStamp = 317467328642
	react.Author = author.PublicKey()
	react.Attorney = attorney.PublicKey()
	react.Hash = []byte{1, 2, 3, 4, 5, 8}
	react.Reaction = 10
	react.Sign(attorney)
	react.AppendFee(attorney, 7836548723687436)

	bytes := react.Serialize()
	react2 := ParseReact(bytes)

	if react2 == nil || !reflect.DeepEqual(react, *react2) {
		t.Error("React parsing or searializing is broken without wallet")
	}
}

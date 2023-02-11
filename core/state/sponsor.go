package state

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/papirus"
)

func GetOrSetSponsor(found bool, hash crypto.Hash, b *papirus.Bucket, item int64, param []byte) papirus.OperationResult {
	if found {
		if param[0] == 0 { // get
			keys := b.ReadItem(item)
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: true, Data: keys},
			}
		} else if param[0] == 1 { // set
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: false},
			}
		} else { // remove
			return papirus.OperationResult{
				Deleted: &papirus.Item{Bucket: b, Item: item},
				Result:  papirus.QueryResult{Ok: true},
			}
		}
	} else {
		if param[0] == 0 { //get
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: false},
			}
		} else if param[0] == 1 { // set
			contentHash := make([]byte, crypto.Size)
			copy(contentHash[0:crypto.Size], param[1:])
			b.WriteItem(item, contentHash)
			return papirus.OperationResult{
				Added:  &papirus.Item{Bucket: b, Item: item},
				Result: papirus.QueryResult{Ok: true},
			}
		} else { // remove
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: false},
			}
		}
	}
}

type Sponsor struct {
	hs *papirus.HashStore[crypto.Hash]
}

func (w *Sponsor) GetContentHash(hash crypto.Hash) (bool, []byte) {
	response := make(chan papirus.QueryResult)
	ok, keys := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: []byte{0}, Response: response})
	if ok {
		return ok, keys
	}
	return false, nil
}

func (w *Sponsor) Exists(hash crypto.Hash) bool {
	response := make(chan papirus.QueryResult)
	ok, _ := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: []byte{0}, Response: response})
	return ok
}

func (w *Sponsor) SetContentHash(hash crypto.Hash, keys []byte) bool {
	response := make(chan papirus.QueryResult)
	ok, _ := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: append([]byte{1}, hash[:]...), Response: response})
	return ok
}

func (w *Sponsor) RemoveContentHash(hash crypto.Hash) bool {
	response := make(chan papirus.QueryResult)
	ok, _ := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: []byte{2}, Response: response})
	return ok
}

func (w *Sponsor) Close() bool {
	ok := make(chan bool)
	w.hs.Stop <- ok
	return <-ok
}

func NewSponsorShipOfferStore(epoch uint64, bitsForBucket int64) *Sponsor {
	itemsize := int64(crypto.Size)
	nbytes := 56 + int64(1<<bitsForBucket)*(itemsize*6+8)
	bytestore := papirus.NewMemoryStore(nbytes)
	bucketstore := papirus.NewBucketStore(itemsize, 6, bytestore)
	w := &Sponsor{
		hs: papirus.NewHashStore("sponsor", bucketstore, int(bitsForBucket), GetOrSetSponsor),
	}
	w.hs.Start()
	return w
}

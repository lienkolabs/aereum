package state

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/papirus"
)

const (
	delete byte = iota
	exists
	insert
)

func deleteOrInsert(found bool, hash crypto.Hash, b *papirus.Bucket, item int64, param []byte) papirus.OperationResult {
	if found {
		if param[0] == delete { //Delete
			return papirus.OperationResult{
				Deleted: &papirus.Item{Bucket: b, Item: item},
				Result:  papirus.QueryResult{Ok: true},
			}
		} else if param[0] == exists { // exists?
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: true},
			}
		} else { // insert
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: false},
			}
		}
	} else {
		if param[0] == insert {
			b.WriteItem(item, hash[:])
			return papirus.OperationResult{
				Added:  &papirus.Item{Bucket: b, Item: item},
				Result: papirus.QueryResult{Ok: true},
			}
		} else {
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: false},
			}
		}
	}
}

type hashVault struct {
	hs *papirus.HashStore[crypto.Hash]
}

func (w *hashVault) ExistsHash(hash crypto.Hash) bool {
	response := make(chan papirus.QueryResult)
	ok, _ := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: []byte{exists}, Response: response})
	return ok
}

func (w *hashVault) ExistsToken(token crypto.Token) bool {
	hash := crypto.HashToken(token)
	return w.ExistsHash(hash)
}

func (w *hashVault) InsertHash(hash crypto.Hash) bool {
	response := make(chan papirus.QueryResult)
	ok, _ := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: []byte{insert}, Response: response})
	return ok
}

func (w *hashVault) InsertToken(token crypto.Token) bool {
	hash := crypto.HashToken(token)
	return w.InsertHash(hash)
}

func (w *hashVault) RemoveHash(hash crypto.Hash) bool {
	response := make(chan papirus.QueryResult)
	ok, _ := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: []byte{delete}, Response: response})
	return ok
}

func (w *hashVault) RemoveToken(token crypto.Token) bool {
	hash := crypto.HashToken(token)
	return w.RemoveHash(hash)
}

func (w *hashVault) Close() bool {
	ok := make(chan bool)
	w.hs.Stop <- ok
	return <-ok
}

func NewHashVault(name string, epoch uint64, bitsForBucket int64) *hashVault {
	nbytes := 56 + (32*6+8)*int64(1<<bitsForBucket)
	bytestore := papirus.NewMemoryStore(nbytes)
	bucketstore := papirus.NewBucketStore(32, 6, bytestore)
	vault := &hashVault{
		hs: papirus.NewHashStore(name, bucketstore, int(bitsForBucket), deleteOrInsert),
	}
	vault.hs.Start()
	return vault

}

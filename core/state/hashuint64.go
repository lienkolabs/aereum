package state

import (
	"encoding/binary"

	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/papirus"
)

func deleteOrInsertExpire(found bool, hash crypto.Hash, b *papirus.Bucket, item int64, param []byte) papirus.OperationResult {
	if found {
		if param[0] == delete { //Delete
			return papirus.OperationResult{
				Deleted: &papirus.Item{Bucket: b, Item: item},
				Result:  papirus.QueryResult{Ok: true},
			}
		} else if param[0] == exists { // exists?
			acc := b.ReadItem(item)
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: true, Data: acc[crypto.Size:]},
			}
		} else { // insert
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: false},
			}
		}
	} else {
		if param[0] == insert {
			value := binary.LittleEndian.Uint64(param[1:])
			acc := make([]byte, crypto.Size+8)
			binary.LittleEndian.PutUint64(acc[crypto.Size:], uint64(value))
			copy(acc[0:crypto.Size], hash[:])
			b.WriteItem(item, acc)
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

type HashUint64Vault struct {
	hs *papirus.HashStore[crypto.Hash]
}

func (w *HashUint64Vault) Exists(hash crypto.Hash) uint64 {
	response := make(chan papirus.QueryResult)
	ok, value := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: []byte{1}, Response: response})
	if !ok {
		return 0
	}
	return binary.LittleEndian.Uint64(value)
}

func (w *HashUint64Vault) Insert(hash crypto.Hash, value uint64) bool {
	response := make(chan papirus.QueryResult)
	param := make([]byte, 8+1)
	param[0] = insert
	binary.LittleEndian.PutUint64(param[1:], value)
	ok, _ := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: param, Response: response})
	return ok
}

func (w *HashUint64Vault) Remove(hash crypto.Hash) bool {
	response := make(chan papirus.QueryResult)
	ok, _ := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: []byte{0}, Response: response})
	return ok
}

func (w *HashUint64Vault) Close() bool {
	ok := make(chan bool)
	w.hs.Stop <- ok
	return <-ok
}

func NewExpireHashVault(name string, epoch uint64, bitsForBucket int64) *HashUint64Vault {
	nbytes := 56 + (40*6+8)*int64(1<<bitsForBucket)
	bytestore := papirus.NewMemoryStore(nbytes)
	bucketstore := papirus.NewBucketStore(40, 6, bytestore)
	vault := &HashUint64Vault{
		hs: papirus.NewHashStore(name, bucketstore, int(bitsForBucket), deleteOrInsertExpire),
	}
	vault.hs.Start()
	return vault
}

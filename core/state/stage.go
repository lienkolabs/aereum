package state

import (
	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/instructions"
	"github.com/lienkolabs/papirus"
)

func getOrSetStage(found bool, hash crypto.Hash, b *papirus.Bucket, item int64, param []byte) papirus.OperationResult {
	get := false
	if len(param) == 0 {
		get = true
	}
	if found {
		if get {
			keys := b.ReadItem(item)
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: true, Data: keys[crypto.Size:]},
			}
		} else {
			updated := make([]byte, crypto.Size+3*crypto.PublicKeySize)
			copy(updated[0:crypto.Size], hash[:])
			copy(updated[crypto.Size:], param)
			b.WriteItem(item, updated)
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: true},
			}

		}
	} else {
		if !get {
			newKeys := make([]byte, crypto.Size+3*crypto.PublicKeySize)
			copy(newKeys[:crypto.Size], hash[:])
			copy(newKeys[crypto.Size:], param)
			b.WriteItem(item, newKeys)
			return papirus.OperationResult{
				Added:  &papirus.Item{Bucket: b, Item: item},
				Result: papirus.QueryResult{Ok: false},
			}
		} else {
			return papirus.OperationResult{
				Result: papirus.QueryResult{Ok: false},
			}
		}
	}
}

type Stage struct {
	hs *papirus.HashStore[crypto.Hash]
}

func (w *Stage) GetKeys(hash crypto.Hash) *instructions.StageKeys {
	response := make(chan papirus.QueryResult)
	ok, keys := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: []byte{}, Response: response})
	if !ok {
		return nil
	}
	stage := instructions.StageKeys{}
	copy(stage.Moderate[:], keys[0:crypto.TokenSize])
	copy(stage.Submit[:], keys[crypto.TokenSize:2*crypto.TokenSize])
	copy(stage.Stage[:], keys[2*crypto.TokenSize:3*crypto.TokenSize])
	stage.Flag = keys[3*crypto.TokenSize]
	return &stage
}

func (w *Stage) Exists(hash crypto.Hash) bool {
	response := make(chan papirus.QueryResult)
	ok, _ := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: []byte{}, Response: response})
	return ok
}

func (w *Stage) SetKeys(hash crypto.Hash, stage *instructions.StageKeys) bool {
	keys := make([]byte, 2*crypto.TokenSize+1)
	copy(keys[0:crypto.TokenSize], stage.Moderate[:])
	copy(keys[crypto.TokenSize:2*crypto.TokenSize], stage.Submit[:])
	copy(keys[2*crypto.TokenSize:3*crypto.TokenSize], stage.Stage[:])
	keys[3*crypto.TokenSize] = stage.Flag
	response := make(chan papirus.QueryResult)
	ok, _ := w.hs.Query(papirus.Query[crypto.Hash]{Hash: hash, Param: keys, Response: response})
	return ok
}

func (w *Stage) Close() bool {
	ok := make(chan bool)
	w.hs.Stop <- ok
	return <-ok
}

func NewMemoryAudienceStore(epoch uint64, bitsForBucket int64) *Stage {
	itemsize := int64(crypto.Size + 3*crypto.TokenSize + 1)
	nbytes := 56 + int64(1<<bitsForBucket)*(itemsize*6+8)
	bytestore := papirus.NewMemoryStore(nbytes)
	bucketstore := papirus.NewBucketStore(itemsize, 6, bytestore)
	w := &Stage{
		hs: papirus.NewHashStore("audience", bucketstore, int(bitsForBucket), getOrSetStage),
	}
	w.hs.Start()
	return w
}

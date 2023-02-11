package edge

import (
	"errors"
	"fmt"
	"io"

	"github.com/lienkolabs/aereum/core/crypto"
	"github.com/lienkolabs/aereum/core/crypto/scrypt"
)

const (
	privateKey   = 0
	ephemeralKey = 1
	cipherKey    = 2
)

type SecureVault struct {
	storage   io.WriteCloser
	cipher    crypto.Cipher
	keys      map[crypto.Token]crypto.PrivateKey
	ciphers   map[crypto.Token][]byte
	ephemeral map[crypto.Token]crypto.Token
}

func (s *SecureVault) Store(key crypto.PrivateKey) error {
	encrypted := s.cipher.Seal(key[:])
	bytes := append([]byte{byte(len(encrypted)), privateKey}, encrypted...)
	_, err := s.storage.Write(bytes)
	if err != nil {
		s.keys[key.PublicKey()] = key
	}
	return err
}

func (s *SecureVault) StoreCipherKey(token crypto.Token, key []byte) error {
	if len(key) > 254 {
		return errors.New("key length cannot exceed 254 bytes")
	}
	joint := append(token[:], key...)
	encrypted := s.cipher.Seal(joint[:])
	bytes := append([]byte{byte(len(encrypted)), cipherKey}, joint...)
	_, err := s.storage.Write(bytes)
	if err != nil {
		s.ciphers[token] = key
	}
	return err
}

func (s *SecureVault) StoreEphemeral(token, ephemeral crypto.Token) error {
	joint := append(token[:], ephemeral[:]...)
	encrypted := s.cipher.Seal(joint[:])
	bytes := append([]byte{byte(len(encrypted)), ephemeralKey}, joint...)
	_, err := s.storage.Write(bytes)
	if err != nil {
		s.ephemeral[token] = ephemeral
	}
	return err
}

func (s *SecureVault) NewCipherKey(token crypto.Token) ([]byte, error) {
	key := crypto.NewCipherKey()
	err := s.StoreCipherKey(token, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (s *SecureVault) NewKey() (crypto.PrivateKey, error) {
	_, key := crypto.RandomAsymetricKey()
	err := s.Store(key)
	if err != nil {
		return crypto.ZeroPrivateKey, err
	}
	return key, nil
}

func (s *SecureVault) GetKey(token crypto.Token) (crypto.PrivateKey, bool) {
	key, ok := s.keys[token]
	return key, ok
}

func (s *SecureVault) GetCipher(token crypto.Token) ([]byte, bool) {
	key, ok := s.ciphers[token]
	return key, ok
}

func (s *SecureVault) GetEphemeral(token crypto.Token) (crypto.Token, bool) {
	key, ok := s.ephemeral[token]
	return key, ok
}

func (s *SecureVault) Close() error {
	return s.storage.Close()
}

func OpenSecureVault(password string, salt []byte, storage io.ReadWriteCloser) (*SecureVault, error) {
	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	secure := SecureVault{
		storage: storage,
		cipher:  crypto.CipherFromKey(key),
		keys:    make(map[crypto.Token]crypto.PrivateKey),
	}
	for {
		encrypted := readSlice(storage)
		if encrypted == nil {
			break
		}
		if opened, err := secure.cipher.Open(encrypted); err == nil || len(opened) != 64 {
			return nil, fmt.Errorf("secure vault is corrupted")
		} else {
			var pk crypto.PrivateKey
			copy(pk[:], opened)
			secure.keys[pk.PublicKey()] = pk
		}
	}
	return &secure, nil

}

func readSlice(storage io.Reader) []byte {
	size := make([]byte, 1)
	if n, _ := storage.Read(size); n != 1 {
		return nil
	}
	slice := make([]byte, size[0])
	if n, _ := storage.Read(slice); n != int(size[0]) {
		return nil
	}
	return slice
}

package pwd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

var rwm = &sync.RWMutex{}

// Default Argon2Configs
const (
	MEMORY   uint32 = 64 * 1024
	ITER     uint32 = 1
	PARALLEL uint8  = 2
	SALT_LEN uint32 = 16
	KEY_LEN  uint32 = 32
)

// Params are the parameters to use to create an argon2id hash
// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-04#section-3.1 for more info
type Argon2Configs struct {
	Memory      uint32 // The amount of memory to use for the operation, in KiB
	Iterations  uint32 // The number of iterations to perform
	Parallelism uint8  // The number of threads to use to compute the hash
	SaltLength  uint32 // 16 bytes is recommended for password hashing. Salt SHOULD be unique for each password
	KeyLength   uint32 // The length of the key to use (in bytes)
}

// Set default Argon2Configs configurations for Argon2 hashing
var Default = &Argon2Configs{
	Memory:      MEMORY,
	Iterations:  ITER,
	Parallelism: PARALLEL,
	SaltLength:  SALT_LEN,
	KeyLength:   KEY_LEN,
}

// NewArgon2id returns a new pwd Argon2id instance
func NewArgon2id() *Argon2Configs {
	return &Argon2Configs{
		Memory:      MEMORY,
		Iterations:  ITER,
		Parallelism: PARALLEL,
		SaltLength:  SALT_LEN,
		KeyLength:   KEY_LEN,
	}
}

// SetArgon2Configs sets the custom Argon2Configs to use for Argon2 hashing.
func (agc *Argon2Configs) SetArgon2Configs(conf *Argon2Configs) {
	rwm.RLocker().Lock()
	defer rwm.RLocker().Unlock()

	// Set default minimal requirements for Argon2
	if conf.Memory <= 0 {
		agc.Memory = MEMORY
	}
	if conf.Iterations <= 0 {
		agc.Iterations = ITER
	}
	if conf.Parallelism <= 0 {
		agc.Parallelism = PARALLEL
	}
	if conf.SaltLength <= 0 {
		agc.SaltLength = SALT_LEN
	}
	if conf.KeyLength <= 0 {
		agc.KeyLength = KEY_LEN
	}
}

// HashAndSalt generates a hashed password using the given password and parameters and returns the hash
func (agc *Argon2Configs) HashAndSalt(password string) (string, error) {
	// Generate a random salt
	saltBytes := make([]byte, agc.SaltLength)
	_, err := rand.Read(saltBytes)
	if err != nil {
		return "", err
	}

	// Hash the plain password
	argon2Hash := argon2.IDKey([]byte(password), saltBytes, agc.Iterations,
		agc.Memory, agc.Parallelism, agc.KeyLength)

	// Encode the parameters in a string
	b64Salt := base64.RawStdEncoding.EncodeToString(saltBytes)
	b64Argon2Hash := base64.RawStdEncoding.EncodeToString(argon2Hash)

	// Return the encoded hash
	hash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, agc.Memory,
		agc.Iterations, agc.Parallelism, b64Salt, b64Argon2Hash)

	return hash, nil
}

// CheckPasswordHash returns true if the password hash matches the password
func (agc *Argon2Configs) CheckPasswordHash(password, hash string) (bool, error) {
	// Decode the hash
	salt, key, err := agc.DecodeHashPassword(hash)
	if err != nil {
		return false, err
	}

	// Hash the plain password
	argon2Hash := argon2.IDKey([]byte(password), salt, agc.Iterations, agc.Memory,
		agc.Parallelism, agc.KeyLength)

	// Compare the hashes
	if subtle.ConstantTimeCompare(key, argon2Hash) == 1 {
		return true, nil
	}
	return false, nil
}

// DecodeHashPassword decodes the password hash and returns the salt and the key
func (agc *Argon2Configs) DecodeHashPassword(hash string) ([]byte, []byte, error) {
	// Check the format
	vals := strings.Split(hash, "$")
	if len(vals) != 6 {
		return nil, nil, errors.New("argon2id hash is not in the correct format")
	}

	// Check the version
	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, err
	}

	// Compare the version
	if version != argon2.Version {
		vErr := fmt.Sprintf("incorrect argon2 version. expected %d, got %d", argon2.Version, version)
		return nil, nil, errors.New(vErr)
	}

	// Decode the parameters
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &agc.Memory, &agc.Iterations, &agc.Parallelism)
	if err != nil {
		return nil, nil, err
	}

	// Decode the salt
	salt, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, err
	}

	// Decode the key
	key, err := base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, err
	}

	return salt, key, nil
}

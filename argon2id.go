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
var agc *Argon2Configs

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

// InitArgon2Configs initializes the Argon2Configs
func InitArgon2Configs(memory, iterations uint32, parallelism uint8, saltLength, keyLength uint32) *Argon2Configs {
	agc = &Argon2Configs{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		SaltLength:  saltLength,
		KeyLength:   keyLength,
	}
	return agc
}

// SetLogInit sets the custom log requirement to initialize the itr logger.
func SetArgon2Configs(memory, iterations uint32, parallelism uint8, saltLength, keyLength uint32) *Argon2Configs {
	rwm.Lock()
	defer rwm.Unlock()

	// Set default minimal requirements for Argon2
	if memory <= 0 {
		memory = MEMORY
	}
	if iterations <= 0 {
		iterations = ITER
	}
	if parallelism <= 0 {
		parallelism = PARALLEL
	}
	if saltLength <= 0 {
		saltLength = SALT_LEN
	}
	if keyLength <= 0 {
		keyLength = KEY_LEN
	}

	// Re-configure the itrlog
	agc = InitArgon2Configs(memory, iterations, parallelism, saltLength, keyLength)
	return agc
}

func init() {
	// Init the default Argon2Configs
	agc = InitArgon2Configs(MEMORY, ITER, PARALLEL, SALT_LEN, KEY_LEN)
}

// HashAndSalt generates a hashed password using the given password and parameters and returns the hash
func HashAndSalt(password string) (string, error) {
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
func CheckPasswordHash(password, hash string) (bool, error) {
	// Decode the hash
	salt, key, err := DecodeHashPassword(hash)
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
func DecodeHashPassword(hash string) ([]byte, []byte, error) {
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

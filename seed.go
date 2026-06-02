package provablyfairgo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
)

const (
	defaultSeedBytes = 32
)

func GenerateSeed(n int) (string, error) {
	if n <= defaultSeedBytes {
		return "", errors.New("seed n must be positive")
	}

	seed := make([]byte, n)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	return hex.EncodeToString(seed), nil
}

type SeedPart struct {
	Namespace string
	Key       string
	Value     string
}

func CommitSeed(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func CommitSeedWithPrefix(seed string) string {
	return "sha256:" + CommitSeed(seed)
}

func BuildFinalSeed(serverSeed string, parts []SeedPart) ([]byte, error) {
	if serverSeed == "" {
		return nil, errors.New("server seed is required")
	}

	payload, err := BuildCanonicalSeedPayload(parts)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, []byte(serverSeed))
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

func BuildFinalSeedHex(serverSeed string, parts []SeedPart) (string, error) {
	finalSeed, err := BuildFinalSeed(serverSeed, parts)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(finalSeed), nil
}

func OrderedSeedParts(namespace string, values map[string]string) ([]SeedPart, error) {
	if namespace == "" {
		return nil, errors.New("namespace is required")
	}

	if len(values) == 0 {
		return nil, errors.New("value are required")
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		if key == "" {
			return nil, errors.New("seed part key is required")
		}
		keys = append(keys, key)
	}

	sort.Strings(keys)

	parts := make([]SeedPart, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, SeedPart{
			Namespace: namespace,
			Key:       key,
			Value:     values[key],
		})
	}
	return parts, nil
}

func BuildCanonicalSeedPayload(parts []SeedPart) ([]byte, error) {
	if len(parts) == 0 {
		return nil, errors.New("seed parts are required")
	}

	payload := make([]byte, 0)
	payload = appendLengthPrefixed(payload, []byte("final-seed"))

	for _, part := range parts {
		if part.Namespace == "" {
			return nil, errors.New("seed part namespace is required")
		}

		if part.Key == "" {
			return nil, errors.New("seed part key is required")
		}

		if part.Value == "" {
			return nil, errors.New("seed part value is required")
		}

		payload = appendLengthPrefixed(payload, []byte(part.Namespace))
		payload = appendLengthPrefixed(payload, []byte(part.Key))
		payload = appendLengthPrefixed(payload, []byte(part.Value))
	}
	return payload, nil
}

func appendLengthPrefixed(dst []byte, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))

	dst = append(dst, length[:]...)
	dst = append(dst, value...)

	return dst
}

func VerifySeedCommitment(seed, commitment string) bool {
	return hmac.Equal([]byte(CommitSeed(seed)), []byte(commitment))
}

func VerifyFinalSeed(serverSeed string, parts []SeedPart, expectedFinalSeed []byte) bool {
	finalSeed, err := BuildFinalSeed(serverSeed, parts)
	if err != nil {
		return false
	}

	if len(finalSeed) != len(expectedFinalSeed) {
		return false
	}

	for ind := range finalSeed {
		if finalSeed[ind] != expectedFinalSeed[ind] {
			return false
		}
	}
	return true
}

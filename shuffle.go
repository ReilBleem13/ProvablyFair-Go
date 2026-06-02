package provablyfairgo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
)

func Shuffle[T any](items []T, finalSeed []byte, nonce uint64) ([]T, []int, error) {
	if len(items) == 0 {
		return nil, nil, errors.New("items are required")
	}

	order, err := ShuffleOrder(len(items), finalSeed, nonce)
	if err != nil {
		return nil, nil, err
	}

	shuffled, err := ApplyOrder(items, order)
	if err != nil {
		return nil, nil, err
	}
	return shuffled, order, nil
}

func ShuffleOrder(n int, finalSeed []byte, nonce uint64) ([]int, error) {
	if n <= 0 {
		return nil, errors.New("cards are required")
	}
	if len(finalSeed) == 0 {
		return nil, errors.New("final seed is required")
	}

	order := make([]int, n)
	for ind := 0; ind < n; ind++ {
		order[ind] = ind
	}

	rng := hmacRNG{
		seed:  finalSeed,
		nonce: nonce,
	}

	for i := len(order) - 1; i > 0; i-- {
		j, err := rng.Intn(i + 1)
		if err != nil {
			return nil, err
		}
		order[i], order[j] = order[j], order[i]
	}
	return order, nil
}

func VerifyShuffleOrder(length int, finalSeed []byte, nonce uint64, expectedOrder []int) bool {
	order, err := ShuffleOrder(length, finalSeed, nonce)
	if err != nil {
		return false
	}

	if len(order) != len(expectedOrder) {
		return false
	}

	for ind := range order {
		if order[ind] != expectedOrder[ind] {
			return false
		}
	}
	return true
}

// RNG нужен, чтобы из finalSeed получать много случайных чисел.
// алгоритм FY shuffe каждый раз просит случаный индекс от 0 до i.
type hmacRNG struct {
	// finalSeed, является ключом HMAC.
	seed []byte
	// Номер конкретного перемешивания.
	nonce uint64
	// Cчетчик блоков, каждый вызов HMAC дает 32 байта,
	// когда байты заканчиватся, увеличивается counter и позволяет получать следующий кусок.
	counter uint64
	// Место куда помещаются еще неиспользованные байты.
	buffer []byte
}

// result := value % uint64(n) является самым простым способом, но может давать перекос, если
// количество возможных value не делится ровно на n.
// -uint64(n) % uint64(n) == (2^64 - n) % n == 2^64 % n
func (r *hmacRNG) Intn(n int) (int, error) {
	if n <= 0 {
		return 0, errors.New("n must be positive")
	}

	threshold := -uint64(n) % uint64(n)

	for {
		value := r.nextUint64()
		if value >= threshold {
			return int(value % uint64(n)), nil
		}
	}
}

// Метод превращает поток байтов в число uint64.
func (r *hmacRNG) nextUint64() uint64 {
	for len(r.buffer) < 8 {
		block := r.nextBlock()
		r.buffer = append(r.buffer, block...)
	}

	value := binary.BigEndian.Uint64(r.buffer[:8])
	r.buffer = r.buffer[8:]
	return value
}

// Метод генерирует один блок случайных байтов.
func (r *hmacRNG) nextBlock() []byte {
	message := "nonce:" + strconv.FormatUint(r.nonce, 10) +
		"|counter:" + strconv.FormatUint(r.counter, 10)

	mac := hmac.New(sha256.New, r.seed)
	_, _ = mac.Write([]byte(message))
	r.counter++
	return mac.Sum(nil)
}

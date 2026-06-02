package provablyfairgo

import "errors"

func ApplyOrder[T any](items []T, order []int) ([]T, error) {
	if len(items) == 0 {
		return nil, errors.New("items are required")
	}
	if len(order) != len(items) {
		return nil, errors.New("order length does not match items length")
	}

	seen := make([]bool, len(items))
	ordered := make([]T, len(items))
	for targetIndex, sourceIndex := range order {
		if sourceIndex < 0 || sourceIndex >= len(items) {
			return nil, errors.New("order index is out of range")
		}
		if seen[sourceIndex] {
			return nil, errors.New("duplicate order index")
		}
		seen[sourceIndex] = true
		ordered[targetIndex] = items[sourceIndex]
	}
	return ordered, nil
}

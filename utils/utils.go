package utils

import (
	"fmt"
	"strconv"
)

func BinToDec(b string) (uint64, error) {
	return strconv.ParseUint(b, 2, 64)
}

func HexToBin(hexWord string) (result string, ferr error) {
	var start, end int

	toBin := func(s string) (string, error) {
		n, err := strconv.ParseUint(s, 16, 64)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%08b", n), nil
	}

	for i := range hexWord {
		if i != 0 && i&1 == 0 {
			end = i
			r, err := toBin(hexWord[start:end])
			if err != nil {
				ferr = err
				return
			}
			result += r
			start = end
		}
	}
	r, err := toBin(hexWord[start:])
	if err != nil {
		ferr = err
		return
	}
	result += r
	return
}

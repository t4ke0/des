package key

import (
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"
)

// PermutedChoiceONE permutation choice one.
var PermutedChoiceONE = []int{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
}

var PermutedChoiceTWO = []int{
	14, 17, 11, 24, 01, 05, 03, 28,
	15, 06, 21, 10, 23, 19, 12, 04,
	26, 8, 16, 07, 27, 20, 13, 02,
	41, 52, 31, 37, 47, 55, 30, 40,
	51, 45, 33, 48, 44, 49, 39, 56,
	34, 53, 46, 42, 50, 36, 29, 32,
}

// HexKeySize size of the generated key in hex decimal.
const HexKeySize = 16

// DesHexKey type alias of string.
type DesHexKey string

// generateInitialKey generating the raw key in hex decimal.
func generateInitalKey() (k DesHexKey) {
	rand.Seed(time.Now().UnixNano())

	var count int

	for count < HexKeySize {
		h := strconv.FormatInt(int64(rand.Intn(16)), 16)
		k += DesHexKey(h)
		count++
	}
	log.Printf("debug init hex key %v", k)
	return
}

func (dk DesHexKey) hexTobin(begin, end *int) (string, error) {
	hexNum := dk[*begin:*end]
	o, err := strconv.ParseUint(string(hexNum), 16, 64)
	if err != nil {
		return "", err
	}
	*begin = *end
	return fmt.Sprintf("%08b", o), nil
}

func (dk DesHexKey) Binary() (DesBinKey, error) {
	var (
		begin int
		end   int
	)
	var binKey string
	for c := range dk {
		if 1&c == 0 && c != 0 {
			end = c
			o, err := dk.hexTobin(&begin, &end)
			if err != nil {
				return "", err
			}
			binKey += o
		}
		if begin == len(dk)-2 {
			end = len(dk)
			o, err := dk.hexTobin(&begin, &end)
			if err != nil {
				return "", err
			}
			binKey += o
		}
	}
	return DesBinKey(binKey), nil
}

// DesBinKey des key in binary.
type DesBinKey string

func (dbk DesBinKey) SetPermutedChoiceONE() (key DesBinKey) {
	for _, n := range PermutedChoiceONE {
		key += DesBinKey(dbk[n-1])
	}
	return
}

// String
func (dbk DesBinKey) String() string {
	return string(dbk)
}

var shiftTimes = 16

func (dbk DesBinKey) SplitAndShift() []DesBinKey {
	s1 := dbk[len(dbk)/2:]
	s2 := dbk[:len(dbk)/2]

	shiftBinNum := func(bin string, num int) string {
		return string(bin[num:]) + string(bin[:num])
	}

	var result []DesBinKey

	var shiftNum int
	for count := 1; count <= shiftTimes; count++ {
		if count == 1 || count == 2 || count == 9 || count == 16 {
			shiftNum = 1
		} else {
			shiftNum = 2
		}

		out := shiftBinNum(string(s1), shiftNum)
		s1 = DesBinKey(out)
		out2 := shiftBinNum(string(s2), shiftNum)
		s2 = DesBinKey(out2)

		result = append(result, s1+s2)
	}

	return result
}

func (dbk DesBinKey) SetPermutedChoiceTWO() (key DesBinKey) {
	for _, i := range PermutedChoiceTWO {
		key += DesBinKey(dbk[i-1])
	}
	return
}

// DesGenKeys generates DES keys. by providing the number of keys you want.
func DesGenKeys(initKey DesHexKey, num int) ([]DesBinKey, error) {
	shiftTimes = num
	var binKey DesBinKey
	if initKey == "" {
		key, err := generateInitalKey().Binary()
		if err != nil {
			return []DesBinKey{}, err
		}
		binKey = key
	} else {
		var err error
		binKey, err = initKey.Binary()
		if err != nil {
			return []DesBinKey{}, err
		}
	}
	var keys []DesBinKey
	for _, n := range binKey.SetPermutedChoiceONE().SplitAndShift() {
		keys = append(keys, n.SetPermutedChoiceTWO())
	}
	return keys, nil
}

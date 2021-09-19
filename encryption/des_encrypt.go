package encryption

import (
	"fmt"

	"github.com/t4ke0/des/key"
	"github.com/t4ke0/des/utils"
)

var (
	IP = []int{
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7,
	}

	SelectionTable = []int{
		32, 1, 2, 3, 4, 5,
		4, 5, 6, 7, 8, 9,
		8, 9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32, 1,
	}

	S1BOX = [][]int{
		[]int{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		[]int{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		[]int{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		[]int{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	}

	S2BOX = [][]int{
		[]int{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		[]int{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		[]int{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		[]int{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	}

	S3BOX = [][]int{
		[]int{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		[]int{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		[]int{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		[]int{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	}
	S4BOX = [][]int{
		[]int{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		[]int{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		[]int{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		[]int{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	}
	S5BOX = [][]int{
		[]int{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		[]int{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		[]int{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		[]int{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	}
	S6BOX = [][]int{
		[]int{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		[]int{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		[]int{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		[]int{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 3},
	}

	S7BOX = [][]int{
		[]int{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		[]int{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		[]int{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		[]int{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	}

	S8BOX = [][]int{
		[]int{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		[]int{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		[]int{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		[]int{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	}

	boxMap = map[int][][]int{
		1: S1BOX,
		2: S2BOX,
		3: S3BOX,
		4: S4BOX,
		5: S5BOX,
		6: S6BOX,
		7: S7BOX,
		8: S8BOX,
	}

	sBoxPermutation = []int{
		16, 7, 20, 21,
		29, 12, 28, 17,
		1, 15, 23, 26,
		5, 18, 31, 10,
		2, 8, 24, 14,
		32, 27, 3, 9,
		19, 13, 30, 6,
		22, 11, 4, 25,
	}

	finalPermutation = []int{
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25,
	}
)

func applyIP(block string) (result string) {
	for _, index := range IP {
		result += string(block[index-1])
	}
	return
}

func f(rblock string, key key.DesBinKey) (string, error) {
	var stResult string
	for _, i := range SelectionTable {
		stResult += string(rblock[i-1])
	}
	if len(stResult) != 48 {
		panic("error f need to expend the size of the block to be 48 bit")
	}

	// key to decimal
	kd, err := utils.BinToDec(key.String())
	if err != nil {
		return "", err
	}

	// block to decimal
	bd, err := utils.BinToDec(stResult)
	if err != nil {
		return "", err
	}

	xorResult, err := utils.HexToBin(fmt.Sprintf("%x", bd^kd))
	if err != nil {
		return "", err
	}

	var boxes []string
	const boxBits = 6

	// TODO: factorize this process.

	count := 0
	begin := 0
	for i := range xorResult {
		if count == boxBits {
			boxes = append(boxes, xorResult[begin:i])
			count = 0
			begin = i
		}
		count++
	}
	boxes = append(boxes, xorResult[begin:])

	var outB string

	for i, b := range boxes {
		row, err := utils.BinToDec(fmt.Sprintf("%c%c", b[0], b[len(b)-1]))
		if err != nil {
			return "", err
		}
		col, err := utils.BinToDec(fmt.Sprintf("%s", b[1:len(b)-1]))
		if err != nil {
			return "", err
		}

		bresult, err := utils.HexToBin(fmt.Sprintf("%x", boxMap[i+1][int(row)][int(col)]))
		if err != nil {
			return "", err
		}
		outB += bresult
	}
	var result string

	for _, n := range sBoxPermutation {
		result += string(outB[n-1])
	}

	return result, nil
}

/*
	Ln = Rn-1
	Rn = Ln-1 XOR f(Rn-1Kn)
*/

func leftrightComputation(piBlock string, keys []key.DesBinKey) (string, error) {
	l, r := piBlock[:len(piBlock)/2], piBlock[len(piBlock)/2:]

	for _, kn := range keys {
		fv, err := f(r, kn)
		if err != nil {
			return "", err
		}
		leftAsDec, err := utils.BinToDec(l)
		if err != nil {
			return "", err
		}
		fvAsDec, err := utils.BinToDec(fv)
		if err != nil {
			return "", err
		}

		rightXORresult, err := utils.HexToBin(fmt.Sprintf("%x", leftAsDec^fvAsDec))
		if err != nil {
			return "", err
		}
		r = rightXORresult
	}

	result := r + l
	return result, nil
}

func applyFinalPermutation(leftrightResult string) (result string) {

	for _, n := range finalPermutation {
		result += string(leftrightResult[n-1])
	}

	return
}

type Des struct {
	Block string
	Keys  []key.DesBinKey
}

func (d Des) Encrypt() (string, error) {
	r := applyIP(d.Block)
	preresult, err := leftrightComputation(r, d.Keys)
	if err != nil {
		return "", err
	}

	result := applyFinalPermutation(preresult)
	return result, nil
}

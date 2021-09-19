package main

import (
	"encoding/hex"
	"flag"
	"log"
	"strconv"

	"github.com/t4ke0/des/encryption"
	"github.com/t4ke0/des/key"
	"github.com/t4ke0/des/utils"
)

// NOTE: at the moment we are accepting only 64bit messages. in the future the
// program will accept message that are longer than that.

// msg := "68656c6c6f776f72"

func main() {

	var textMessage string
	var k string

	flag.StringVar(&textMessage, "msg", "", "message to encrypt")
	flag.StringVar(&k, "hexkey", "", "hex 64bit key")

	flag.Parse()

	if textMessage == "" {
		log.Printf("here %v %v", textMessage == "", textMessage)
		flag.PrintDefaults()
		return
	}

	// hexKey := hex.EncodeToString([]byte(k))

	keys, err := key.DesGenKeys(key.DesHexKey(k), 16)
	if err != nil {
		log.Fatal(err)
	}

	binMsg, err := utils.HexToBin(hex.EncodeToString([]byte(textMessage)))
	if err != nil {
		log.Fatal(err)
	}

	blocks := splitMsgInto64Blocks(&binMsg)

	var finalRslt string
	for _, b := range blocks {
		des := encryption.Des{
			Block: b,
			Keys:  keys,
		}

		result, err := des.Encrypt()
		if err != nil {
			log.Fatal(err)
		}

		hexResult, err := binTOhex(result)
		if err != nil {
			log.Fatal(err)
		}

		finalRslt += hexResult
	}

	log.Printf("result %v", finalRslt)
}

// for debug only
// REMOVEME
func binTOhex(k string) (string, error) {
	n, err := strconv.ParseUint(k, 2, 64)
	if err != nil {
		return "", err
	}

	return strconv.FormatUint(n, 16), nil
}

func splitMsgInto64Blocks(initBlock *string) (blocks []string) {
	const blocksize = 64
	if len(*initBlock) < 64 {
		return []string{}
	}

	for *initBlock != "" {
		if len(*initBlock) < blocksize {
			left := blocksize - len(*initBlock)
			for i := 0; i < left; i++ {
				*initBlock += "0"
			}
		}
		block := (*initBlock)[:blocksize]
		blocks = append(blocks, block)
		*initBlock = (*initBlock)[blocksize:]
	}

	return blocks
}

package main

import (
	"log"

	"github.com/t4ke0/des/key"
)

func main() {
	keys, err := key.DesGenKeys(16)
	if err != nil {
		log.Fatal(err)
	}
	for _, n := range keys {
		log.Printf("%v\n\n", n)
	}

}

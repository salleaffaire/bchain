package main

// A little bit of go -- YAY!

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Block
// -------------------------------------------------------------------------------------------------------------
type Block struct {
	key  []byte
	data []byte
	hash []byte
}

func BlockCreate(key []byte, data []byte, previousHash []byte, hashFunction func(data []byte, previousHash []byte) []byte) *Block {
	block := &Block{key: key, data: data, hash: hashFunction(data, previousHash)}
	return block
}

func (b *Block) Print() {
	fmt.Printf("Key:       %s\n", hex.EncodeToString(b.key))
	fmt.Printf("Data:      %s\n", hex.EncodeToString(b.data))
	fmt.Printf("Signature: %s\n", hex.EncodeToString(b.hash[:]))
}

// Hash functions
// -------------------------------------------------------------------------------------------------------------

func getHashZero() []byte {
	rval := []byte{}
	return rval[:]
}

func Hash(data []byte, previousHash []byte) []byte {
	hash := sha256.Sum256(append(data, previousHash[:]...))
	return hash[:]
}

func HashBCrypt(data []byte, previousHash []byte) []byte {
	rval, _ := bcrypt.GenerateFromPassword(append(data, previousHash[:]...), 16)
	return rval[:]
}

// Block chain
// -------------------------------------------------------------------------------------------------------------

type BlockChain struct {
	chain        []Block
	hashFunction func(data []byte, previousHash []byte) []byte
}

func New(hashFunction func(data []byte, previousHash []byte) []byte) BlockChain {
	return BlockChain{chain: []Block{}, hashFunction: hashFunction}
}

func (bc *BlockChain) Add(key []byte, data []byte) {
	var block *Block
	if len(bc.chain) == 0 {
		block = BlockCreate(key, data, getHashZero(), bc.hashFunction)
	} else {
		block = BlockCreate(key, data, bc.chain[len(bc.chain)-1].hash, bc.hashFunction)
	}
	bc.chain = append(bc.chain, *block)
}

func (bc *BlockChain) Print() {
	for index, block := range bc.chain {
		fmt.Printf("Block number %d\n", index)
		block.Print()
	}
}

// Main
// -------------------------------------------------------------------------------------------------------------

func main() {
	// Create block chain
	blockChain := New(HashBCrypt)

	blockChain.Add([]byte("password"), []byte("aSecureWord"))
	blockChain.Add([]byte("username"), []byte("luc.martel"))
	blockChain.Add([]byte("ammount"), []byte("100"))

	blockChain.Print()
}

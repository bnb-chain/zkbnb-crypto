package src

import (
	"errors"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"syscall/js"
)

func KeccakHash(value []byte) []byte {
	hashVal := crypto.Keccak256Hash(value)
	return hashVal[:]
}

func ComputeAccountNameHash(accountName string) (res string, err error) {
	words := strings.Split(accountName, ".")
	if len(words) != 2 {
		return "", errors.New("[AccountNameHash] invalid account name")
	}

	q, _ := big.NewInt(0).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	rootNode := make([]byte, 32)
	hashOfBaseNode := KeccakHash(append(rootNode, KeccakHash([]byte(words[1]))...))

	baseNode := big.NewInt(0).Mod(big.NewInt(0).SetBytes(hashOfBaseNode), q)
	baseNodeBytes := make([]byte, 32)
	baseNode.FillBytes(baseNodeBytes)

	nameHash := KeccakHash([]byte(words[0]))
	subNameHash := KeccakHash(append(baseNodeBytes, nameHash...))

	subNode := big.NewInt(0).Mod(big.NewInt(0).SetBytes(subNameHash), q)
	subNodeBytes := make([]byte, 32)
	subNode.FillBytes(subNodeBytes)

	res = common.Bytes2Hex(subNodeBytes)
	return res, nil
}

func AccountNameHash() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "invalid swap params"
		}
		// xxx.legend
		name := args[0].String()
		nameHash, err := ComputeAccountNameHash(name)
		if err != nil {
			return err.Error()
		}
		return nameHash
	})
	return helperFunc
}

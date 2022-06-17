package src

import (
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"strings"
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
	buf := make([]byte, 32)
	label := KeccakHash([]byte(words[0]))
	res = common.Bytes2Hex(
		KeccakHash(append(
			KeccakHash(append(buf,
				KeccakHash([]byte(words[1]))...)), label...)))
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

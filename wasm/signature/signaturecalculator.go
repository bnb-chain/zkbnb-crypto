package signature

import (
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"strings"
)

func CalculateL1AddressBySignature(signatureBody, l1Signature string) common.Address {
	message := accounts.TextHash([]byte(signatureBody))
	//Decode from signature string to get the signature byte array
	signatureContent, err := hexutil.Decode(l1Signature)
	if err != nil {
		return [20]byte{}
	}
	signatureContent[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	//Calculate the public key from the signature and source string
	signaturePublicKey, err := crypto.SigToPub(message, signatureContent)
	if err != nil {
		return [20]byte{}
	}

	//Calculate the address from the public key
	publicAddress := crypto.PubkeyToAddress(*signaturePublicKey)
	return publicAddress
}
func GetHex10FromInt64(value int64) string {
	v := hexutil.EncodeUint64(uint64(value))
	v = strings.Replace(v, "0x", "", 1)
	//不够8位的前补0
	return fmt.Sprintf("0x%08s", v)
}

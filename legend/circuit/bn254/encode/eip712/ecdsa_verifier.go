package eip712

import (
	"encoding/hex"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

type Secp256k1Circuit struct {
	SIG []frontend.Variable
	MSG []frontend.Variable // MSG: Hashes
	PK  []frontend.Variable // PK: public key
}

func VerifyEcdsaSignatureSecp256k1(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
	sig := joinBytes(inputs[:65])
	msg := joinBytes(inputs[65:97])
	pubKey := joinBytes(inputs[97:])
	pk, err := crypto.Ecrecover(msg, sig)
	if err != nil {
		return err
	}

	if crypto.VerifySignature(pk, msg, sig[:64]) && hex.EncodeToString(pubKey) == hex.EncodeToString(pk) {
		results[0].SetInt64(1)
	} else {
		results[0].SetInt64(0)
	}
	return nil
}

func joinBytes(inputs []*big.Int) []byte {
	bytes := make([]byte, len(inputs))
	for i := 0; i < len(inputs); i++ {
		bytes[i] = uint8(inputs[i].Uint64())
	}
	return bytes
}

func init() {
	hint.Register(VerifyEcdsaSignatureSecp256k1)
}

func (circuit *Secp256k1Circuit) Verify(api frontend.API) (frontend.Variable, error) {

	inputs := make([]frontend.Variable, 0)
	inputs = append(inputs, circuit.SIG...)
	inputs = append(inputs, circuit.MSG...)
	inputs = append(inputs, circuit.PK...)

	res, err := api.Compiler().NewHint(VerifyEcdsaSignatureSecp256k1, 1, inputs...)
	if err != nil {
		return nil, err
	}
	return res[0], nil
}

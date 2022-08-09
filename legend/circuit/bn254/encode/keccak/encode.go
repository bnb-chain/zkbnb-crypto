// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package abi

import (
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/encode/abi"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

type Circuit struct {
	AbiId  frontend.Variable
	Values []frontend.Variable // variable name
	Bytes  []frontend.Variable `gnark:",public"` // abi object
	Name   frontend.Variable   `gnark:",public"` // abi object
}

func init() {
	hint.Register(GenerateKeccakHint)
}

func (circuit *Circuit) Define(api frontend.API) error {
	encoder, err := abi.NewAbiEncoder(api, circuit.AbiId)
	if err != nil {
		return err
	}

	res, err := encoder.Pack(api, circuit.Name, circuit.Values...)
	if err != nil {
		return err
	}

	keccakRes, err := api.Compiler().NewHint(GenerateKeccakHint, 32, res...)

	for i := range keccakRes {
		api.AssertIsEqual(keccakRes[i], circuit.Bytes[i])
	}
	return nil
}

func GenerateKeccakHint(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
	preImageBytes := make([]byte, 0)

	for _, bi := range inputs {
		if len(bi.Bytes()) > 1 {
			continue
		}
		preImageBytes = append(preImageBytes, uint8(bi.Uint64()))
	}

	keccakSum := crypto.Keccak256(preImageBytes)
	for i := range keccakSum {
		results[i].SetUint64(uint64(keccakSum[i]))
	}
	return nil
}

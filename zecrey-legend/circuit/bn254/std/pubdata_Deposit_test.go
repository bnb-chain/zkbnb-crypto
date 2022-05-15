/*
 * Copyright © 2021 Zecrey Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package std

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	mimc2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"testing"
)

type DepositPubDataConstraints struct {
	TxInfo    DepositTxConstraints
	FinalHash Variable
}

func (circuit DepositPubDataConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	CollectPubDataFromDeposit(api, 1, circuit.TxInfo, &hFunc)
	hash := hFunc.Sum()
	api.AssertIsEqual(hash, circuit.FinalHash)
	return nil
}

func TestCollectPubDataFromDeposit(t *testing.T) {
	accountName := make([]byte, 32)
	copy(accountName, "sher")
	accountNameHash := crypto.Keccak256Hash(accountName)
	//accountNameHashInt := ffmath.Mod(new(big.Int).SetBytes(accountNameHash[:]), curve.Modulus)
	amountInt := big.NewInt(10000000)
	txInfo := &DepositTx{
		AccountIndex:    1,
		AccountNameHash: accountNameHash[:],
		AssetId:         1,
		AssetAmount:     amountInt,
	}
	var buf bytes.Buffer
	buf.Write([]byte{TxTypeDeposit})
	buf.Write(new(big.Int).SetInt64(txInfo.AccountIndex).FillBytes(make([]byte, 4)))
	buf.Write(new(big.Int).SetInt64(txInfo.AssetId).FillBytes(make([]byte, 2)))
	buf.Write(amountInt.FillBytes(make([]byte, 16)))
	a := new(big.Int).SetBytes(buf.Bytes())
	buf.Reset()
	buf.Write(a.FillBytes(make([]byte, 32)))
	buf.Write(accountNameHash[:])
	hFunc := mimc2.NewMiMC()
	fmt.Println(len(amountInt.Bytes()))
	hFunc.Write(buf.Bytes())
	hashVal := hFunc.Sum(nil)
	var circuit, witness DepositPubDataConstraints
	witness.TxInfo = SetDepositTxWitness(txInfo)
	witness.FinalHash = hashVal
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

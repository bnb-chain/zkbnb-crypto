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

type FullExitPubDataConstraints struct {
	TxInfo    FullExitTxConstraints
	FinalHash Variable
}

func (circuit FullExitPubDataConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	CollectPubDataFromFullExit(api, 1, circuit.TxInfo, &hFunc)
	hash := hFunc.Sum()
	api.AssertIsEqual(hash, circuit.FinalHash)
	return nil
}

func TestCollectPubDataFromFullExit(t *testing.T) {
	accountName := make([]byte, 32)
	copy(accountName, "sher")
	accountNameHash := crypto.Keccak256Hash(accountName)
	txInfo := &FullExitTx{
		AccountIndex:    1,
		AccountNameHash: accountNameHash[:],
		AssetId:         1,
		AssetAmount:     big.NewInt(100),
	}
	var buf bytes.Buffer
	buf.Write([]byte{TxTypeFullExit})
	buf.Write(new(big.Int).SetInt64(txInfo.AccountIndex).FillBytes(make([]byte, 4)))
	buf.Write(new(big.Int).SetInt64(txInfo.AssetId).FillBytes(make([]byte, 2)))
	buf.Write(txInfo.AssetAmount.FillBytes(make([]byte, 16)))
	a := new(big.Int).SetBytes(buf.Bytes()).FillBytes(make([]byte, 32))
	hFunc := mimc2.NewMiMC()
	buf.Reset()
	buf.Write(a)
	buf.Write(txInfo.AccountNameHash)
	hFunc.Write(buf.Bytes())
	hashVal := hFunc.Sum(nil)
	var circuit, witness FullExitPubDataConstraints
	witness.TxInfo = SetFullExitTxWitness(txInfo)
	witness.FinalHash = hashVal
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

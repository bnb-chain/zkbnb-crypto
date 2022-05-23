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
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"math/big"
	"testing"
)

type RegisterZNSPubDataConstraints struct {
	TxInfo    RegisterZnsTxConstraints
	FinalHash Variable
}

func (circuit RegisterZNSPubDataConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	CollectPubDataFromRegisterZNS(api, 1, circuit.TxInfo, &hFunc)
	hash := hFunc.Sum()
	api.AssertIsEqual(hash, circuit.FinalHash)
	return nil
}

func TestCollectPubDataFromRegisterZNS(t *testing.T) {
	accountName := make([]byte, 32)
	copy(accountName, "sher")
	accountNameHash := crypto.Keccak256Hash(accountName)
	seed := "pubKey"
	sk, err := curve.GenerateEddsaPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	txInfo := &RegisterZnsTx{
		AccountIndex:    1,
		AccountName:     accountName,
		AccountNameHash: accountNameHash[:],
		PubKey:          &sk.PublicKey,
	}
	var buf bytes.Buffer
	buf.Write([]byte{TxTypeRegisterZns})
	buf.Write(new(big.Int).SetInt64(txInfo.AccountIndex).FillBytes(make([]byte, 4)))
	a := buf.Bytes()
	buf.Reset()
	buf.Write(new(big.Int).SetBytes(a).FillBytes(make([]byte, 32)))
	buf.Write(txInfo.AccountName)
	buf.Write(txInfo.AccountNameHash)
	buf.Write(sk.PublicKey.A.X.Marshal())
	hFunc := mimc2.NewMiMC()
	hFunc.Write(buf.Bytes())
	hashVal := hFunc.Sum(nil)
	var circuit, witness RegisterZNSPubDataConstraints
	witness.TxInfo = SetRegisterZnsTxWitness(txInfo)
	witness.FinalHash = hashVal
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

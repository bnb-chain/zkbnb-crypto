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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"testing"
)

type DepositNftPubDataConstraints struct {
	TxInfo    DepositNftTxConstraints
	FinalHash Variable
}

func (circuit DepositNftPubDataConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	CollectPubDataFromDepositNft(api, 1, circuit.TxInfo, &hFunc)
	hash := hFunc.Sum()
	api.AssertIsEqual(hash, circuit.FinalHash)
	return nil
}

func TestCollectPubDataFromDepositNft(t *testing.T) {
	accountName := make([]byte, 32)
	copy(accountName, "sher")
	accountNameHash := crypto.Keccak256Hash(accountName)
	txInfo := &DepositNftTx{
		AccountIndex:        1,
		AccountNameHash:     accountNameHash[:],
		NftIndex:            1,
		NftContentHash:      accountNameHash[:],
		NftL1Address:        "0xd5Aa3B56a2E2139DB315CdFE3b34149c8ed09171",
		NftL1TokenId:        big.NewInt(123),
		CreatorTreasuryRate: 50,
	}
	var buf bytes.Buffer
	buf.Write([]byte{TxTypeDepositNft})
	buf.Write(new(big.Int).SetInt64(txInfo.AccountIndex).FillBytes(make([]byte, 4)))
	buf.Write(new(big.Int).SetInt64(txInfo.NftIndex).FillBytes(make([]byte, 5)))
	buf.Write(common.FromHex(txInfo.NftL1Address))
	buf.Write(new(big.Int).SetInt64(txInfo.CreatorTreasuryRate).FillBytes(make([]byte, 2)))
	a := buf.Bytes()
	buf.Reset()
	buf.Write(a)
	buf.Write(txInfo.AccountNameHash)
	buf.Write(txInfo.NftContentHash)
	buf.Write(txInfo.NftL1TokenId.FillBytes(make([]byte, 32)))
	hFunc := mimc2.NewMiMC()
	hFunc.Write(buf.Bytes())
	hashVal := hFunc.Sum(nil)
	var circuit, witness DepositNftPubDataConstraints
	witness.TxInfo = SetDepositNftTxWitness(txInfo)
	witness.FinalHash = hashVal
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"math/big"
	"testing"
)

type WithdrawNftPubDataConstraints struct {
	TxInfo    WithdrawNftTxConstraints
	FinalHash Variable
}

func (circuit WithdrawNftPubDataConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	CollectPubDataFromWithdrawNft(api, 1, circuit.TxInfo, &hFunc)
	hash := hFunc.Sum()
	api.AssertIsEqual(hash, circuit.FinalHash)
	return nil
}

func TestCollectPubDataFromWithdrawNft(t *testing.T) {
	accountName := make([]byte, 32)
	copy(accountName, "sher")
	accountNameHash := crypto.Keccak256Hash(accountName)
	txInfo := &WithdrawNftTx{
		AccountIndex:      1,
		NftIndex:          2,
		NftContentHash:    accountNameHash[:],
		NftL1Address:      "0xd5Aa3B56a2E2139DB315CdFE3b34149c8ed09171",
		NftL1TokenId:      big.NewInt(100),
		ToAddress:         "0xd5Aa3B56a2E2139DB315CdFE3b34149c8ed09171",
		ProxyAddress:      "0xd5Aa3B56a2E2139DB315CdFE3b34149c8ed09171",
		GasAccountIndex:   3,
		GasFeeAssetId:     2,
		GasFeeAssetAmount: 100,
	}
	var buf bytes.Buffer
	buf.Write([]byte{TxTypeWithdrawNft})
	buf.Write(new(big.Int).SetInt64(txInfo.AccountIndex).FillBytes(make([]byte, 4)))
	buf.Write(new(big.Int).SetInt64(txInfo.NftIndex).FillBytes(make([]byte, 5)))
	buf.Write(common.FromHex(txInfo.NftL1Address))
	buf.Write(common.FromHex(txInfo.ToAddress)[:2])
	a := new(big.Int).SetBytes(buf.Bytes()).FillBytes(make([]byte, 32))
	buf.Reset()
	buf.Write(common.FromHex(txInfo.ToAddress)[2:])
	buf.Write(common.FromHex(txInfo.ProxyAddress)[:14])
	b := new(big.Int).SetBytes(buf.Bytes()).FillBytes(make([]byte, 32))
	buf.Reset()
	buf.Write(common.FromHex(txInfo.ProxyAddress)[14:])
	buf.Write(new(big.Int).SetInt64(txInfo.GasAccountIndex).FillBytes(make([]byte, 4)))
	buf.Write(new(big.Int).SetInt64(txInfo.GasFeeAssetId).FillBytes(make([]byte, 2)))
	buf.Write(new(big.Int).SetInt64(txInfo.GasFeeAssetAmount).FillBytes(make([]byte, 2)))
	c := new(big.Int).SetBytes(buf.Bytes()).FillBytes(make([]byte, 32))
	fmt.Println(new(big.Int).SetBytes(b).String())
	buf.Reset()
	buf.Write(a)
	buf.Write(b)
	buf.Write(c)
	hFunc := mimc2.NewMiMC()
	buf.Write(txInfo.NftContentHash)
	fmt.Println(ffmath.Mod(new(big.Int).SetBytes(txInfo.NftContentHash), curve.Modulus).String())
	buf.Write(txInfo.NftL1TokenId.FillBytes(make([]byte, 32)))
	fmt.Println(txInfo.NftL1TokenId.String())
	hFunc.Write(buf.Bytes())
	hashVal := hFunc.Sum(nil)
	var circuit, witness WithdrawNftPubDataConstraints
	witness.TxInfo = SetWithdrawNftTxWitness(txInfo)
	witness.FinalHash = hashVal
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

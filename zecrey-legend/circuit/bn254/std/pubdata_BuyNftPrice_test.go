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
	"math/big"
	"testing"
)

type BuyNftPubDataConstraints struct {
	TxInfo    BuyNftTxConstraints
	FinalHash Variable
}

func (circuit BuyNftPubDataConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	CollectPubDataFromBuyNft(api, 1, circuit.TxInfo, &hFunc)
	hash := hFunc.Sum()
	api.AssertIsEqual(hash, circuit.FinalHash)
	return nil
}

func TestCollectPubDataFromBuyNft(t *testing.T) {
	txInfo := &BuyNftTx{
		BuyerAccountIndex:     1,
		OwnerAccountIndex:     2,
		NftIndex:              1,
		AssetId:               1,
		AssetAmount:           100,
		TreasuryFeeRate:       30,
		TreasuryFeeAmount:     200,
		TreasuryAccountIndex:  2,
		CreatorTreasuryRate:   20,
		CreatorTreasuryAmount: 100,
		GasAccountIndex:       3,
		GasFeeAssetId:         2,
		GasFeeAssetAmount:     100,
	}
	var buf bytes.Buffer
	buf.Write([]byte{TxTypeBuyNft})
	buf.Write(new(big.Int).SetInt64(txInfo.BuyerAccountIndex).FillBytes(make([]byte, 4)))
	buf.Write(new(big.Int).SetInt64(txInfo.OwnerAccountIndex).FillBytes(make([]byte, 4)))
	buf.Write(new(big.Int).SetInt64(txInfo.NftIndex).FillBytes(make([]byte, 5)))
	buf.Write(new(big.Int).SetInt64(txInfo.AssetId).FillBytes(make([]byte, 2)))
	buf.Write(new(big.Int).SetInt64(txInfo.AssetAmount).FillBytes(make([]byte, 5)))
	buf.Write(new(big.Int).SetInt64(txInfo.GasAccountIndex).FillBytes(make([]byte, 4)))
	buf.Write(new(big.Int).SetInt64(txInfo.GasFeeAssetId).FillBytes(make([]byte, 2)))
	buf.Write(new(big.Int).SetInt64(txInfo.GasFeeAssetAmount).FillBytes(make([]byte, 2)))
	buf.Write(new(big.Int).SetInt64(txInfo.TreasuryAccountIndex).FillBytes(make([]byte, 4)))
	buf.Write(new(big.Int).SetInt64(txInfo.TreasuryFeeAmount).FillBytes(make([]byte, 2)))
	buf.Write(new(big.Int).SetInt64(txInfo.CreatorTreasuryAmount).FillBytes(make([]byte, 2)))
	hFunc := mimc2.NewMiMC()
	hFunc.Write(buf.Bytes())
	hashVal := hFunc.Sum(nil)
	var circuit, witness BuyNftPubDataConstraints
	witness.TxInfo = SetBuyNftTxWitness(txInfo)
	witness.FinalHash = hashVal
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

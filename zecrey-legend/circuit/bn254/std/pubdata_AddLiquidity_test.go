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

type AddLiquidityPubDataConstraints struct {
	TxInfo    AddLiquidityTxConstraints
	FinalHash Variable
}

func (circuit AddLiquidityPubDataConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	CollectPubDataFromAddLiquidity(api, 1, circuit.TxInfo, &hFunc)
	hash := hFunc.Sum()
	api.AssertIsEqual(hash, circuit.FinalHash)
	return nil
}

func TestCollectPubDataFromAddLiquidity(t *testing.T) {
	txInfo := &AddLiquidityTx{
		FromAccountIndex:  1,
		PairIndex:         1,
		AssetAId:          1,
		AssetAAmount:      100,
		AssetBId:          2,
		AssetBAmount:      100,
		LpAmount:          30,
		PoolAAmount:       big.NewInt(1000),
		PoolBAmount:       big.NewInt(1000),
		GasAccountIndex:   3,
		GasFeeAssetId:     1,
		GasFeeAssetAmount: 1000,
	}
	var buf bytes.Buffer
	buf.Write([]byte{TxTypeAddLiquidity})
	buf.Write(new(big.Int).SetInt64(txInfo.FromAccountIndex).FillBytes(make([]byte, 4)))
	buf.Write(new(big.Int).SetInt64(txInfo.PairIndex).FillBytes(make([]byte, 2)))
	buf.Write(new(big.Int).SetInt64(txInfo.AssetAAmount).FillBytes(make([]byte, 5)))
	buf.Write(new(big.Int).SetInt64(txInfo.AssetBAmount).FillBytes(make([]byte, 5)))
	buf.Write(new(big.Int).SetInt64(txInfo.LpAmount).FillBytes(make([]byte, 5)))
	buf.Write(new(big.Int).SetInt64(txInfo.GasAccountIndex).FillBytes(make([]byte, 4)))
	buf.Write(new(big.Int).SetInt64(txInfo.GasFeeAssetId).FillBytes(make([]byte, 2)))
	buf.Write(new(big.Int).SetInt64(txInfo.GasFeeAssetAmount).FillBytes(make([]byte, 2)))
	hFunc := mimc2.NewMiMC()
	hFunc.Write(buf.Bytes())
	hashVal := hFunc.Sum(nil)
	var circuit, witness AddLiquidityPubDataConstraints
	witness.TxInfo = SetAddLiquidityTxWitness(txInfo)
	witness.FinalHash = hashVal
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

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

package transactions

import (
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/zecrey-labs/zecrey-crypto/hash/bn254/zmimc"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/circuit/bn254/std"
)

type BlockConstraints struct {
	// public inputs
	OldRoot         Variable `gnark:",public"`
	NewRoot         Variable `gnark:",public"`
	BlockCommitment Variable `gnark:",public"`
	// tx info
	Txs [NbTxsCountHalf]TxConstraints
}

func (circuit BlockConstraints) Define(api API) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(api.Curve())
	if err != nil {
		return err
	}

	// mimc
	hFunc, err := mimc.NewMiMC(zmimc.SEED, api)
	if err != nil {
		return err
	}

	// TODO verify H: need to optimize
	H := Point{
		X: std.HX,
		Y: std.HY,
	}
	tool := std.NewEccTool(api, params)
	VerifyBlock(tool, api, circuit, hFunc, H)

	return nil
}

func VerifyBlock(
	tool *std.EccTool,
	api API,
	block BlockConstraints,
	hFunc MiMC,
	h Point,
) {
	for i := 0; i < len(block.Txs); i++ {
		VerifyTransaction(tool, api, block.Txs[i], hFunc, h, 0)
		hFunc.Reset()
	}
}

func SetBlockWitness(txs []TxConstraints) (witness BlockConstraints, err error) {
	for i := 0; i < len(txs); i++ {
		witness.Txs[i] = txs[i]
	}
	return witness, nil
}

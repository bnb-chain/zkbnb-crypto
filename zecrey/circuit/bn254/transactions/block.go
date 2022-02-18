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
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// TODO verify H: need to optimize
	H := Point{
		X: std.HX,
		Y: std.HY,
	}
	tool := std.NewEccTool(api, params)
	VerifyBlock(tool, api, circuit, hFunc, H, NilHash)

	return nil
}

func VerifyBlock(
	tool *std.EccTool,
	api API,
	block BlockConstraints,
	hFunc MiMC,
	h Point,
	nilHash Variable,
) {
	api.AssertIsEqual(block.OldRoot, block.Txs[0].AccountRootBefore)
	api.AssertIsEqual(block.NewRoot, block.Txs[NbTxsCountHalf-1].AccountRootAfter)
	for i := 0; i < NbTxsCountHalf-1; i++ {
		api.AssertIsEqual(block.Txs[i].AccountRootAfter, block.Txs[i+1].AccountRootBefore)
		// TODO commitment
		api.FromBinary()
		VerifyTransaction(tool, api, block.Txs[i], hFunc, h, nilHash)
		hFunc.Reset()
	}
	VerifyTransaction(tool, api, block.Txs[NbTxsCountHalf-1], hFunc, h, nilHash)
}

func SetBlockWitness(txs []TxConstraints) (witness BlockConstraints, err error) {
	for i := 0; i < len(txs); i++ {
		witness.Txs[i] = txs[i]
	}
	return witness, nil
}

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
	"log"
)

type BlockInfo struct {
	BlockNumber     uint64
	BlockHeaderHash []byte
	OnChainOpsRoot  []byte
	OldRoot         []byte
	NewRoot         []byte
	BlockCommitment []byte
	CreatedAt       uint64
	Txs             []*Tx
}

type BlockConstraints struct {
	// public inputs
	OldRoot         Variable `gnark:",public"`
	NewRoot         Variable `gnark:",public"`
	BlockCommitment Variable `gnark:",public"`
	// tx info
	Txs [TxsCountPerBlock]TxConstraints
	// TODO add basic info
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
	api.AssertIsEqual(block.NewRoot, block.Txs[TxsCountPerBlock-1].AccountRootAfter)
	VerifyTransaction(tool, api, block.Txs[0], hFunc, h, nilHash)
	for i := 1; i < TxsCountPerBlock; i++ {
		api.AssertIsEqual(block.Txs[i-1].AccountRootAfter, block.Txs[i].AccountRootBefore)
		// TODO commitment
		VerifyTransaction(tool, api, block.Txs[i], hFunc, h, nilHash)
		hFunc.Reset()
	}
}

func SetBlockWitness(blockInfo *BlockInfo) (witness BlockConstraints, err error) {
	witness.BlockCommitment = blockInfo.BlockCommitment
	witness.OldRoot = blockInfo.OldRoot
	witness.NewRoot = blockInfo.NewRoot
	for i := 0; i < len(blockInfo.Txs); i++ {
		witness.Txs[i], err = SetTxWitness(blockInfo.Txs[i])
		if err != nil {
			log.Println("[SetBlockWitness] unable to set tx witness:", err)
			return witness, err
		}
	}
	return witness, nil
}

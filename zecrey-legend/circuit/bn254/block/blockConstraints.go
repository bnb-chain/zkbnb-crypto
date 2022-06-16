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

package block

import (
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/std"
	"log"
)

type BlockConstraints struct {
	BlockNumber     Variable
	CreatedAt       Variable
	OldStateRoot    Variable `gnark:",public"`
	NewStateRoot    Variable `gnark:",public"`
	BlockCommitment Variable `gnark:",public"`
	Txs             [NbTxsPerBlock]TxConstraints
}

func (circuit BlockConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	pubdataHashFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	err = VerifyBlock(api, circuit, hFunc, pubdataHashFunc)
	if err != nil {
		return err
	}
	return nil
}

func VerifyBlock(
	api API,
	block BlockConstraints,
	hFunc MiMC,
	pubdataHashFunc MiMC,
) (err error) {
	var (
		onChainOpsCount       Variable
		isOnChainOp           Variable
		pendingCommitmentData [std.PubDataSizePerTx*NbTxsPerBlock + 5]Variable
		count                 = 4
	)
	// write basic info into hFunc
	pendingCommitmentData[0] = block.BlockNumber
	pendingCommitmentData[1] = block.CreatedAt
	pendingCommitmentData[2] = block.OldStateRoot
	pendingCommitmentData[3] = block.NewStateRoot
	api.AssertIsEqual(block.OldStateRoot, block.Txs[0].StateRootBefore)
	api.AssertIsEqual(block.NewStateRoot, block.Txs[NbTxsPerBlock-1].StateRootAfter)
	onChainOpsCount = 0
	isOnChainOp, pendingPubData, err := VerifyTransaction(api, block.Txs[0], hFunc, block.CreatedAt)
	if err != nil {
		log.Println("[VerifyBlock] unable to verify block:", err)
		return err
	}
	for i := 0; i < std.PubDataSizePerTx; i++ {
		pendingCommitmentData[count] = pendingPubData[i]
		count++
	}
	onChainOpsCount = api.Add(onChainOpsCount, isOnChainOp)
	for i := 1; i < NbTxsPerBlock; i++ {
		api.AssertIsEqual(block.Txs[i-1].StateRootAfter, block.Txs[i].StateRootBefore)
		hFunc.Reset()
		isOnChainOp, pendingPubData, err = VerifyTransaction(api, block.Txs[i], hFunc, block.CreatedAt)
		if err != nil {
			log.Println("[VerifyBlock] unable to verify block:", err)
			return err
		}
		for j := 0; j < std.PubDataSizePerTx; j++ {
			pendingCommitmentData[count] = pendingPubData[i]
			count++
		}
		onChainOpsCount = api.Add(onChainOpsCount, isOnChainOp)
	}
	pendingCommitmentData[count] = onChainOpsCount
	//commitment := pubdataHashFunc.Sum()
	commitments, _ := api.Compiler().NewHint(std.Keccak256, 1, pendingCommitmentData[:]...)
	api.AssertIsEqual(commitments[0], block.BlockCommitment)
	return nil
}

func SetBlockWitness(oBlock *Block) (witness BlockConstraints, err error) {
	witness = BlockConstraints{
		BlockNumber:     oBlock.BlockNumber,
		CreatedAt:       oBlock.CreatedAt,
		OldStateRoot:    oBlock.OldStateRoot,
		NewStateRoot:    oBlock.NewStateRoot,
		BlockCommitment: oBlock.BlockCommitment,
	}
	for i := 0; i < NbTxsPerBlock; i++ {
		witness.Txs[i], err = SetTxWitness(oBlock.Txs[i])
		if err != nil {
			log.Println("[SetBlockWitness] unable to set tx witness: ", err.Error())
			return witness, err
		}
	}
	return witness, nil
}

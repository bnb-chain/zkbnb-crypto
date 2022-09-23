/*
 * Copyright © 2022 ZkBNB Protocol
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

package solidity

import (
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/bnb-chain/zkbnb-crypto/circuit"
)

func TestCompileCircuit(t *testing.T) {
	differentBlockSizes := []int{1, 10}
	gasAssetIds := []int{0, 1}
	for i := 0; i < len(differentBlockSizes); i++ {
		var blockConstrains circuit.BlockConstraints
		blockConstrains.TxsCount = differentBlockSizes[i]
		blockConstrains.Txs = make([]circuit.TxConstraints, blockConstrains.TxsCount)
		for i := 0; i < blockConstrains.TxsCount; i++ {
			blockConstrains.Txs[i] = circuit.GetZeroTxConstraint()
		}
		blockConstrains.GasAssetIds = gasAssetIds
		blockConstrains.Gas = circuit.GetZeroGasConstraints(len(gasAssetIds))
		oR1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &blockConstrains, frontend.IgnoreUnconstrainedInputs())
		if err != nil {
			panic(err)
		}
		fmt.Printf("Number of constraints: %d\n", oR1cs.GetNbConstraints())
	}
}

func TestExportSol(t *testing.T) {
	differentBlockSizes := []int{1, 10}
	for i := 0; i < len(differentBlockSizes); i++ {
		var blockConstrains circuit.BlockConstraints
		blockConstrains.TxsCount = differentBlockSizes[i]
		blockConstrains.Txs = make([]circuit.TxConstraints, blockConstrains.TxsCount)
		for i := 0; i < blockConstrains.TxsCount; i++ {
			blockConstrains.Txs[i] = circuit.GetZeroTxConstraint()
		}
		oR1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &blockConstrains, frontend.IgnoreUnconstrainedInputs())
		if err != nil {
			panic(err)
		}

		pk, vk, err := groth16.Setup(oR1cs)
		if err != nil {
			panic(err)
		}
		{
			f, err := os.Create("zkbnb" + fmt.Sprint(differentBlockSizes[i]) + ".vk")
			if err != nil {
				panic(err)
			}
			_, err = vk.WriteRawTo(f)
			if err != nil {
				panic(err)
			}
		}
		{
			f, err := os.Create("zkbnb" + fmt.Sprint(differentBlockSizes[i]) + ".pk")
			if err != nil {
				panic(err)
			}
			_, err = pk.WriteRawTo(f)
			if err != nil {
				panic(err)
			}
		}

		{
			f, err := os.Create("ZkBNBVerifier" + fmt.Sprint(differentBlockSizes[i]) + ".sol")
			if err != nil {
				panic(err)
			}
			err = vk.ExportSolidity(f)
			if err != nil {
				panic(err)
			}
		}
	}
}

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
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/bnb-chain/zkbnb-crypto/circuit"
)

var optionalBlockSizes = flag.String("blocksizes", "1,10", "block size that will be used for proof generation and verification")

func TestCompileCircuit(t *testing.T) {
	differentBlockSizes := optionalBlockSizesInt()
	gasAssetIds := []int64{0, 1}
	gasAccountIndex := int64(1)
	for i := 0; i < len(differentBlockSizes); i++ {
		var blockConstraints circuit.BlockConstraints
		blockConstraints.TxsCount = differentBlockSizes[i]
		blockConstraints.Txs = make([]circuit.TxConstraints, blockConstraints.TxsCount)
		for i := 0; i < blockConstraints.TxsCount; i++ {
			blockConstraints.Txs[i] = circuit.GetZeroTxConstraint()
		}
		blockConstraints.GasAssetIds = gasAssetIds
		blockConstraints.GasAccountIndex = gasAccountIndex
		blockConstraints.Gas = circuit.GetZeroGasConstraints(gasAssetIds)
		oR1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &blockConstraints, frontend.IgnoreUnconstrainedInputs())
		if err != nil {
			panic(err)
		}
		fmt.Printf("Number of constraints: %d\n", oR1cs.GetNbConstraints())
	}
}

func TestExportSol(t *testing.T) {
	exportSol(optionalBlockSizesInt())
}

func TestExportSolSmall(t *testing.T) {
	differentBlockSizes := []int{1}
	exportSol(differentBlockSizes)
}

func exportSol(differentBlockSizes []int) {
	gasAssetIds := []int64{0, 1}
	gasAccountIndex := int64(1)
	sessionName := "zkbnb"
	for i := 0; i < len(differentBlockSizes); i++ {
		var blockConstraints circuit.BlockConstraints
		blockConstraints.TxsCount = differentBlockSizes[i]
		blockConstraints.Txs = make([]circuit.TxConstraints, blockConstraints.TxsCount)
		for i := 0; i < blockConstraints.TxsCount; i++ {
			blockConstraints.Txs[i] = circuit.GetZeroTxConstraint()
		}
		blockConstraints.GasAssetIds = gasAssetIds
		blockConstraints.GasAccountIndex = gasAccountIndex
		blockConstraints.Gas = circuit.GetZeroGasConstraints(gasAssetIds)
		oR1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &blockConstraints, frontend.IgnoreUnconstrainedInputs())
		fmt.Printf("Constraints num=%v\n", oR1cs.GetNbConstraints())
		if err != nil {
			panic(err)
		}

		// pk, vk, err := groth16.Setup(oR1cs)
		err = groth16.SetupLazyWithDump(oR1cs, sessionName+fmt.Sprint(differentBlockSizes[i]))
		if err != nil {
			panic(err)
		}
		{
			verifyingKey := groth16.NewVerifyingKey(ecc.BN254)
			f, _ := os.Open(sessionName + fmt.Sprint(differentBlockSizes[i]) + ".vk.save")
			_, err = verifyingKey.ReadFrom(f)
			if err != nil {
				panic(fmt.Errorf("read file error"))
			}
			f.Close()
			f, err := os.Create("ZkBNBVerifier" + fmt.Sprint(differentBlockSizes[i]) + ".sol")
			if err != nil {
				panic(err)
			}
			err = verifyingKey.ExportSolidity(f)
			if err != nil {
				panic(err)
			}
		}
	}
}

func optionalBlockSizesInt() []int {
	blockSizesStr := strings.Split(*optionalBlockSizes, ",")
	blockSizesInt := make([]int, len(blockSizesStr))
	for i := range blockSizesStr {
		v, err := strconv.Atoi(blockSizesStr[i])
		if err != nil {
			panic(err)
		}
		blockSizesInt[i] = v
	}
	return blockSizesInt
}

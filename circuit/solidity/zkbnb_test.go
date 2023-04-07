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
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/bnb-chain/zkbnb-crypto/circuit"
)

var (
	optionalBlockSizes = flag.String("blocksizes", "1,10", "block size that will be used for proof generation and verification")
	batchSize          = flag.String("batchsize", "100000", "number of r1cs files that will be used for proof generation")
	bN                 = flag.Int("bN", 0, "bN is the bits of N Hashes, if we got 1024 hashes to prove, the bN should be set to 10")
)

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
		bn := chooseBN(*bN, differentBlockSizes[i])
		blockConstraints.GKRs.AllocateGKRCircuit(bn)
		blockConstraints.Gas = circuit.GetZeroGasConstraints(gasAssetIds)
		oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &blockConstraints, frontend.IgnoreUnconstrainedInputs(), frontend.WithGKRBN(bn))
		if err != nil {
			panic(err)
		}
		t.Logf("Number of constraints: %d\n", oR1cs.GetNbConstraints())
	}
}

func TestExportSol(t *testing.T) {
	exportSol(t, optionalBlockSizesInt())
}

func TestExportSolSmall(t *testing.T) {
	differentBlockSizes := []int{1}
	exportSol(t, differentBlockSizes)
}

func exportSol(t *testing.T, differentBlockSizes []int) {
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
		bn := chooseBN(*bN, differentBlockSizes[i])
		t.Logf("block size: %d, bN: %d", differentBlockSizes[i], bn)
		blockConstraints.GKRs.AllocateGKRCircuit(bn)
		oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &blockConstraints, frontend.IgnoreUnconstrainedInputs(), frontend.WithGKRBN(bn))
		if err != nil {
			panic(err)
		}
		t.Logf("Constraints num=%d\n", oR1cs.GetNbConstraints())
		nbPublicVariables := oR1cs.GetNbPublicVariables()
		nbSecretVariables := oR1cs.GetNbSecretVariables()
		nbInternalVariables := oR1cs.GetNbInternalVariables()
		t.Logf("Variables total=%d, nbPublicVariables=%d, nbSecretVariables=%d, nbInternalVariables=%d\n",
			nbPublicVariables+nbSecretVariables+nbInternalVariables, nbPublicVariables, nbSecretVariables, nbInternalVariables)
		sessionNameForBlock := sessionName + fmt.Sprint(differentBlockSizes[i])

		oR1cs.Lazify()

		batch, _ := strconv.Atoi(*batchSize)

		err = oR1cs.SplitDumpBinary(sessionNameForBlock, batch)

		oR1cs2 := groth16.NewCS(ecc.BN254)
		oR1cs2.LoadFromSplitBinaryConcurrent(sessionNameForBlock, oR1cs.GetNbR1C(), batch, runtime.NumCPU())
		if err != nil {
			panic(err)
		}

		f, err := os.Create(sessionNameForBlock + ".r1cslen")
		if err != nil {
			panic(err)
		}
		_, err = f.WriteString(fmt.Sprint(oR1cs2.GetNbR1C()))
		if err != nil {
			panic(err)
		}
		f.Close()

		err = groth16.SetupDumpKeys(oR1cs2, sessionNameForBlock)
		if err != nil {
			panic(err)
		}

		{
			verifyingKey := groth16.NewVerifyingKey(ecc.BN254)
			f, _ := os.Open(sessionNameForBlock + ".vk.save")
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

func chooseBN(bNFromFlag int, blockSize int) int {
	if bNFromFlag != 0 {
		return bNFromFlag
	}
	bn, err := circuit.ChooseBN(blockSize)
	if err != nil {
		panic(err)
	}
	return bn
}

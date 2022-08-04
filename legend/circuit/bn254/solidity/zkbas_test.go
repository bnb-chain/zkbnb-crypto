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

package solidity

import (
	"fmt"
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/block"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"os"
	"testing"
	"text/template"
)

type PlonkProofForDiffBlockSize struct {
	Vks []plonk.VerifyingKey
	Sizes []uint16
}

func TestExportSolGroth16(t *testing.T) {
	differentBlockSizes := []int{1}
	for i := 0; i < len(differentBlockSizes); i++ {
		var circuit block.BlockConstraints
		circuit.TxsCount = differentBlockSizes[i]
		circuit.Txs = make([]block.TxConstraints, circuit.TxsCount)
		for i := 0; i < circuit.TxsCount; i++ {
			circuit.Txs[i] = block.GetZeroTxConstraint()
		}
		oR1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
		if err != nil {
			panic(err)
		}

		pk, vk, err := groth16.Setup(oR1cs)
		if err != nil {
			panic(err)
		}
		{
			f, err := os.Create("zkbas" + fmt.Sprint(differentBlockSizes[i]) + ".vk")
			if err != nil {
				panic(err)
			}
			_, err = vk.WriteRawTo(f)
			if err != nil {
				panic(err)
			}
		}
		{
			f, err := os.Create("zkbas" + fmt.Sprint(differentBlockSizes[i]) + ".pk")
			if err != nil {
				panic(err)
			}
			_, err = pk.WriteRawTo(f)
			if err != nil {
				panic(err)
			}
		}

		{
			f, err := os.Create("ZkbasVerifier" + fmt.Sprint(differentBlockSizes[i]) + ".sol")
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

func TestExportSolPlonk(t *testing.T) {
	differentBlockSizes := []uint16{1, 10}
	var p PlonkProofForDiffBlockSize
	p.Sizes = differentBlockSizes
	p.Vks = make([]plonk.VerifyingKey, len(p.Sizes))
	for i := 0; i < len(differentBlockSizes); i++ {
		var circuit block.BlockConstraints
		circuit.TxsCount = int(differentBlockSizes[i])
		circuit.Txs = make([]block.TxConstraints, circuit.TxsCount)
		for i := 0; i < circuit.TxsCount; i++ {
			circuit.Txs[i] = block.GetZeroTxConstraint()
		}
		oScs, err := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
		if err != nil {
			panic(err)
		}
		srs, _ := test.NewKZGSRS(oScs)
		pk, vk, err := plonk.Setup(oScs, srs)
		if err != nil {
			panic(err)
		}
		{
			f, err := os.Create("zkbas" + fmt.Sprint(differentBlockSizes[i]) + ".vk_plonk")
			if err != nil {
				panic(err)
			}
			_, err = vk.WriteTo(f)
			if err != nil {
				panic(err)
			}
			p.Vks[i] = vk
		}
		{
			f, err := os.Create("zkbas" + fmt.Sprint(differentBlockSizes[i]) + ".pk_plonk")
			if err != nil {
				panic(err)
			}
			_, err = pk.WriteTo(f)
			if err != nil {
				panic(err)
			}
		}
		{
			f, err := os.Create("zkbas" + fmt.Sprint(differentBlockSizes[i]) + ".srs_plonk")
			if err != nil {
				panic(err)
			}
			_, err = srs.WriteTo(f)
			if err != nil {
				panic(err)
			}
		}
	}
	f, err := os.Create("ZkbasPlonkVerifier" + ".sol")
	if err != nil {
		panic(err)
	}
	tmpl, err := template.New("").Parse(zkbasPlonkVerifierTemplate)
	if err != nil {
		panic(err)
	}
	// execute template
	err = tmpl.Execute(f, p)
	if err != nil {
		panic(err)
	}
}
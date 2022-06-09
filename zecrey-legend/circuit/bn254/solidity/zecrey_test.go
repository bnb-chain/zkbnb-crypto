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
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/suite"
	"github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/block"
	"log"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestExportSol(t *testing.T) {
	var circuit block.BlockConstraints

	oR1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(oR1cs)
	if err != nil {
		panic(err)
	}
	{
		f, err := os.Create("zecrey-legend.vk")
		if err != nil {
			panic(err)
		}
		_, err = vk.WriteRawTo(f)
		if err != nil {
			panic(err)
		}
	}
	{
		f, err := os.Create("zecrey-legend.pk")
		if err != nil {
			panic(err)
		}
		_, err = pk.WriteRawTo(f)
		if err != nil {
			panic(err)
		}
	}

	{
		f, err := os.Create("ZecreyVerifier.sol")
		if err != nil {
			panic(err)
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			panic(err)
		}
	}
}

type ExportSolidityTestSuite struct {
	suite.Suite

	// backend
	backend *backends.SimulatedBackend

	// verifier contract
	verifierContract *ZecreyVerifier

	// groth16 gnark objects
	vk      groth16.VerifyingKey
	pk      groth16.ProvingKey
	circuit block.BlockConstraints
	r1cs    frontend.CompiledConstraintSystem
}

func TestRunExportSolidityTestSuite(t *testing.T) {
	suite.Run(t, new(ExportSolidityTestSuite))
}

func (t *ExportSolidityTestSuite) SetupTest() {

	const gasLimit uint64 = 8000499

	// setup simulated backend
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	auth, _ := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))

	t.backend = backends.NewSimulatedBackend(core.GenesisAlloc{addr: {Balance: big.NewInt(params.Ether)}}, 10000000)

	// deploy verifier contract
	_, _, v, err := DeployZecreyVerifier(auth, t.backend)
	t.NoError(err, "deploy verifier contract failed")
	t.verifierContract = v
	t.backend.Commit()

	t.r1cs, err = frontend.Compile(ecc.BN254, r1cs.NewBuilder, &t.circuit, frontend.IgnoreUnconstrainedInputs())
	t.NoError(err, "compiling R1CS failed")

	fmt.Println("constraints:", t.r1cs.GetNbConstraints())

	// read proving and verifying keys
	t.pk = groth16.NewProvingKey(ecc.BN254)
	{
		f, _ := os.Open("zecrey-legend.pk")
		_, err = t.pk.ReadFrom(f)
		f.Close()
		t.NoError(err, "reading proving key failed")
	}
	t.vk = groth16.NewVerifyingKey(ecc.BN254)
	{
		f, _ := os.Open("zecrey-legend.vk")
		_, err = t.vk.ReadFrom(f)
		f.Close()
		t.NoError(err, "reading verifying key failed")
	}

}

func (t *ExportSolidityTestSuite) TestVerifyProof() {
	txInfo := ``
	var oTx *block.Tx
	err := json.Unmarshal([]byte(txInfo), &oTx)
	if err != nil {
		panic(err)
	}
	blockInfo := &block.Block{
		BlockNumber: 1,
	}
	blockInfo.Txs[0] = oTx

	// create a valid proof
	var blockWitness block.BlockConstraints

	//tx := block.PrepareBlockSmall()
	blockWitness, err = block.SetBlockWitness(blockInfo)
	if err != nil {
		panic(err)
	}
	var verifyWitness block.BlockConstraints
	verifyWitness.BlockCommitment = blockInfo.BlockCommitment
	witness, err := frontend.NewWitness(&blockWitness, ecc.BN254)
	if err != nil {
		panic(err)
	}
	vWitness, err := frontend.NewWitness(&verifyWitness, ecc.BN254, frontend.PublicOnly())
	if err != nil {
		panic(err)
	}
	elapse := time.Now()
	fmt.Println("start prove")
	proof, err := groth16.Prove(t.r1cs, t.pk, witness)
	t.NoError(err, "proving failed")
	fmt.Println(time.Since(elapse))
	// ensure gnark (Go) code verifies it
	elapse = time.Now()
	fmt.Println("start verify")
	err = groth16.Verify(proof, t.vk, vWitness)
	t.NoError(err, "verifying failed")
	log.Println(time.Since(elapse))
	log.Println("verification process pass")
	// get proof bytes
	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	// solidity contract inputs
	var (
		a     [2]*big.Int
		b     [2][2]*big.Int
		c     [2]*big.Int
		input [3]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	fmt.Println(a[0].String())
	fmt.Println(a[1].String())
	fmt.Println(b[0][0].String())
	fmt.Println(b[0][1].String())
	fmt.Println(b[1][0].String())
	fmt.Println(b[1][1].String())
	fmt.Println(c[0].String())
	fmt.Println(c[1].String())

	// public witness
	input[2] = new(big.Int).SetBytes(blockInfo.BlockCommitment)

	// call the contract
	fmt.Println("start verify proof on-chain")
	res, err := t.verifierContract.VerifyProof(nil, a, b, c, input)
	t.NoError(err, "calling verifier on chain gave error")
	t.True(res, "calling verifier on chain didn't succeed")

}

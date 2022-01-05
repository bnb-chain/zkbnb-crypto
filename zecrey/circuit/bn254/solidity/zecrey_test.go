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
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/suite"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/circuit/bn254/transactions"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestExportSol(t *testing.T) {
	var circuit transactions.BlockConstraints

	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}
	{
		f, err := os.Create("zecrey.vk")
		if err != nil {
			panic(err)
		}
		_, err = vk.WriteRawTo(f)
		if err != nil {
			panic(err)
		}
	}
	{
		f, err := os.Create("zecrey.pk")
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
	verifierContract *Zecrey

	// groth16 gnark objects
	vk      groth16.VerifyingKey
	pk      groth16.ProvingKey
	circuit transactions.BlockConstraints
	r1cs    frontend.CompiledConstraintSystem
}

func TestRunExportSolidityTestSuite(t *testing.T) {
	suite.Run(t, new(ExportSolidityTestSuite))
}

func (t *ExportSolidityTestSuite) SetupTest() {

	const gasLimit uint64 = 8000029

	// setup simulated backend
	key, _ := crypto.GenerateKey()
	auth := bind.NewKeyedTransactor(key)
	genesis := map[common.Address]core.GenesisAccount{
		auth.From: {Balance: big.NewInt(10000000000)},
	}
	t.backend = backends.NewSimulatedBackend(genesis, gasLimit)

	// deploy verifier contract
	_, _, v, err := DeployVerifier(auth, t.backend)
	t.NoError(err, "deploy verifier contract failed")
	t.verifierContract = v
	t.backend.Commit()

	t.r1cs, err = frontend.Compile(ecc.BN254, backend.GROTH16, &t.circuit)
	t.NoError(err, "compiling R1CS failed")

	fmt.Println("constraints:", t.r1cs.GetNbConstraints())

	// read proving and verifying keys
	t.pk = groth16.NewProvingKey(ecc.BN254)
	{
		f, _ := os.Open("zecrey.pk")
		_, err = t.pk.ReadFrom(f)
		f.Close()
		t.NoError(err, "reading proving key failed")
	}
	t.vk = groth16.NewVerifyingKey(ecc.BN254)
	{
		f, _ := os.Open("zecrey.vk")
		_, err = t.vk.ReadFrom(f)
		f.Close()
		t.NoError(err, "reading verifying key failed")
	}

}

func (t *ExportSolidityTestSuite) TestVerifyProof() {

	// create a valid proof
	var witness transactions.BlockConstraints

	//tx := transactions.PrepareBlockSmall()
	witness, err := transactions.SetBlockWitness(nil)
	if err != nil {
		panic(err)
	}

	elapse := time.Now()
	fmt.Println("start prove")
	proof, err := groth16.Prove(t.r1cs, t.pk, &witness)
	t.NoError(err, "proving failed")
	fmt.Println(time.Since(elapse))
	// ensure gnark (Go) code verifies it
	elapse = time.Now()
	fmt.Println("start verify")
	err = groth16.Verify(proof, t.vk, &witness)
	t.NoError(err, "verifying failed")
	fmt.Println(time.Since(elapse))
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
		input [2]*big.Int
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

	// public witness
	//input[0] = new(big.Int).SetBytes(tx.OldRoot)
	//input[1] = new(big.Int).SetBytes(tx.NewRoot)

	// call the contract
	fmt.Println("start verify proof on-chain")
	res, err := t.verifierContract.VerifyProof(nil, a, b, c, input)
	t.NoError(err, "calling verifier on chain gave error")
	t.True(res, "calling verifier on chain didn't succeed")

	// (wrong) public witness
	input[0] = new(big.Int).SetUint64(42)
	input[1] = new(big.Int).SetUint64(2)

	// call the contract should fail
	res, err = t.verifierContract.VerifyProof(nil, a, b, c, input)
	t.NoError(err, "calling verifier on chain gave error")
	t.False(res, "calling verifier on chain succeed, and shouldn't have")
}

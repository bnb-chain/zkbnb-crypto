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
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

func TestTxConstraints_Define_Transfer(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit, frontend.IgnoreUnconstrainedInputs)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())

	// test transfer
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := uint64(8)
	r1 := curve.RandomValue()
	_, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(2)
	r2 := curve.RandomValue()
	_, pk3 := twistedElgamal.GenKeyPair()
	b3 := big.NewInt(3)
	r3 := curve.RandomValue()
	b1Enc, err := twistedElgamal.Enc(big.NewInt(int64(b1)), r1, pk1)
	b2Enc, err := twistedElgamal.Enc(b2, r2, pk2)
	b3Enc, err := twistedElgamal.Enc(b3, r3, pk3)
	if err != nil {
		t.Fatal(err)
	}
	fee := uint64(1)
	relation, err := zecrey.NewTransferProofRelation(1, fee)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(b2Enc, pk2, 0, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(b1Enc, pk1, b1, -5, sk1)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(b3Enc, pk3, 0, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := zecrey.ProveTransfer(relation)
	if err != nil {
		t.Fatal(err)
	}
	witness, err = SetTxWitness(proof, TxTypeTransfer, true)
	if err != nil {
		t.Fatal(err)
	}

	//assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs))
}

func TestTxConstraints_Define_Swap(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit, witness TxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit, frontend.IgnoreUnconstrainedInputs)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())

	b_u_A := uint64(8)
	b_u_fee := uint64(4)
	assetAId := uint32(1)
	assetBId := uint32(2)
	assetFeeId := uint32(3)
	b_A_Delta := uint64(1)
	b_B_Delta := uint64(2)
	b_fee_Delta := uint64(1)
	b_Dao_A := uint64(10)
	b_Dao_B := uint64(10)
	feeRate := uint32(3)
	sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_Dao := twistedElgamal.GenKeyPair()
	C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
	C_ufee, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_fee)), curve.RandomValue(), Pk_u)
	relation, err := zecrey.NewSwapRelation(
		C_uA, C_ufee,
		Pk_Dao, Pk_u,
		assetAId, assetBId, assetFeeId,
		b_A_Delta, b_B_Delta, b_fee_Delta, b_u_A, b_u_fee,
		feeRate,
		sk_u,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := zecrey.ProveSwap(relation)
	if err != nil {
		t.Fatal(err)
	}
	// set params
	proof.AddDaoInfo(b_Dao_A, b_Dao_B)

	witness, err = SetTxWitness(proof, TxTypeSwap, true)
	if err != nil {
		t.Fatal(err)
	}

	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs))
}

func TestTxConstraints_Define_AddLiquidity(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit, frontend.IgnoreUnconstrainedInputs)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	b_u_A := uint64(8)
	b_u_B := uint64(4)
	assetAId := uint32(1)
	assetBId := uint32(2)
	b_A_Delta := uint64(1)
	b_B_Delta := uint64(1)
	b_Dao_A := uint64(10)
	b_Dao_B := uint64(10)
	sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_Dao := twistedElgamal.GenKeyPair()
	C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
	C_uB, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_B)), curve.RandomValue(), Pk_u)
	relation, err := zecrey.NewAddLiquidityRelation(
		C_uA, C_uB,
		Pk_Dao, Pk_u,
		assetAId, assetBId,
		b_u_A, b_u_B,
		b_A_Delta, b_B_Delta,
		sk_u,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := zecrey.ProveAddLiquidity(relation)
	if err != nil {
		t.Fatal(err)
	}
	proof.AddDaoInfo(b_Dao_A, b_Dao_B)

	witness, err = SetTxWitness(proof, TxTypeAddLiquidity, true)
	if err != nil {
		t.Fatal(err)
	}

	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs))
}

func TestTxConstraints_Define_RemoveLiquidity(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit, frontend.IgnoreUnconstrainedInputs)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())

	b_u_LP := uint64(1)
	assetAId := uint32(1)
	assetBId := uint32(2)
	b_A_Delta := uint64(1)
	b_B_Delta := uint64(1)
	Delta_LP := uint64(1)
	b_Dao_A := uint64(100)
	b_Dao_B := uint64(100)
	sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_Dao := twistedElgamal.GenKeyPair()
	//C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
	//C_uB, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_B)), curve.RandomValue(), Pk_u)
	C_uLP, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_LP)), curve.RandomValue(), Pk_u)
	relation, err := zecrey.NewRemoveLiquidityRelation(
		C_uLP,
		Pk_Dao, Pk_u,
		b_u_LP,
		Delta_LP,
		b_A_Delta, b_B_Delta,
		assetAId, assetBId,
		sk_u,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := zecrey.ProveRemoveLiquidity(relation)
	if err != nil {
		t.Fatal(err)
	}
	proof.AddDaoInfo(b_Dao_A, b_Dao_B, curve.RandomValue(), curve.RandomValue())

	witness, err = SetTxWitness(proof, TxTypeRemoveLiquidity, true)
	if err != nil {
		t.Fatal(err)
	}

	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs))
}

func TestTxConstraints_Define_Withdraw(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit, frontend.IgnoreUnconstrainedInputs)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())

	sk, pk := twistedElgamal.GenKeyPair()
	b := uint64(8)
	r := curve.RandomValue()
	bEnc, err := twistedElgamal.Enc(big.NewInt(int64(b)), r, pk)
	if err != nil {
		t.Error(err)
	}
	bStar := uint64(2)
	fee := uint64(1)
	addr := "0xE9b15a2D396B349ABF60e53ec66Bcf9af262D449"
	relation, err := zecrey.NewWithdrawRelation(bEnc, pk, b, bStar, sk, 1, addr, fee)
	if err != nil {
		t.Error(err)
	}
	proof, err := zecrey.ProveWithdraw(relation)
	if err != nil {
		t.Error(err)
	}

	witness, err = SetTxWitness(proof, TxTypeWithdraw, true)
	if err != nil {
		t.Fatal(err)
	}

	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs))
}

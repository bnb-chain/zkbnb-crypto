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

package zecrey

import (
	"github.com/stretchr/testify/assert"
	"log"
	"math/big"
	"testing"
	"time"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestSwapProof2_Verify(t *testing.T) {
	b_u_A := uint64(2000)
	assetAId := uint32(1)
	assetBId := uint32(2)
	b_A_Delta := uint64(1000)
	b_B_Delta := uint64(970)
	MinB_B_Delta := uint64(960)
	b_poolA := uint64(40000)
	b_poolB := uint64(40000)
	feeRate := uint32(30)
	treasuryRate := uint32(10)
	GasFee := uint64(30)
	sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_pool := twistedElgamal.GenKeyPair()
	_, Pk_treasury := twistedElgamal.GenKeyPair()
	C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
	b_fee := uint64(1000)
	//b_fee := b_u_A
	C_fee, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), curve.RandomValue(), Pk_u)
	relation, err := NewSwapRelation(
		C_uA,
		Pk_u, Pk_treasury,
		assetAId, assetBId,
		b_A_Delta, b_u_A,
		MinB_B_Delta,
		feeRate, treasuryRate,
		sk_u,
		C_fee,
		b_fee, uint32(2), GasFee,
	)
	if err != nil {
		t.Fatal(err)
	}
	elapse := time.Now()
	proof, err := ProveSwap(relation)
	if err != nil {
		t.Fatal(err)
	}
	// set params
	err = proof.AddPoolInfo(Pk_pool, b_B_Delta, b_poolA, b_poolB)
	if err != nil {
		t.Fatal(err)
	}
	log.Println("prove time:", time.Since(elapse))
	proofStr := proof.String()
	proof2, err := ParseSwapProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, res, "invalid proof")
}

func TestSwapProof2_VerifySameAsset(t *testing.T) {
	b_u_A := uint64(2000)
	assetAId := uint32(1)
	assetBId := uint32(2)
	b_A_Delta := uint64(1000)
	b_B_Delta := uint64(970)
	MinB_B_Delta := uint64(960)
	b_poolA := uint64(40000)
	b_poolB := uint64(40000)
	feeRate := uint32(30)
	treasuryRate := uint32(10)
	GasFee := uint64(1)
	sk_u, Pk_u := twistedElgamal.GenKeyPair()
	_, Pk_pool := twistedElgamal.GenKeyPair()
	_, Pk_treasury := twistedElgamal.GenKeyPair()
	C_uA, _ := twistedElgamal.Enc(big.NewInt(int64(b_u_A)), curve.RandomValue(), Pk_u)
	b_fee := uint64(2000)
	//b_fee := b_u_A
	C_fee := C_uA
	relation, err := NewSwapRelation(
		C_uA,
		Pk_u, Pk_treasury,
		assetAId, assetBId,
		b_A_Delta, b_u_A,
		MinB_B_Delta,
		feeRate, treasuryRate,
		sk_u,
		C_fee,
		b_fee, assetAId, GasFee,
	)
	if err != nil {
		t.Fatal(err)
	}
	elapse := time.Now()
	proof, err := ProveSwap(relation)
	if err != nil {
		t.Fatal(err)
	}
	// set params
	err = proof.AddPoolInfo(Pk_pool, b_B_Delta, b_poolA, b_poolB)
	if err != nil {
		t.Fatal(err)
	}
	log.Println("prove time:", time.Since(elapse))
	proofStr := proof.String()
	proof2, err := ParseSwapProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, res, "invalid proof")
}

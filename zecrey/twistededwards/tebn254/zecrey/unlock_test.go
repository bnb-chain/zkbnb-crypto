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
	"testing"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestUnlockProof_Verify(t *testing.T) {
	sk, _ := twistedElgamal.GenKeyPair()
	chainId := uint32(0)
	assetId := uint32(0)
	balance := uint64(10)
	deltaAmount := uint64(2)
	proof, err := ProveUnlock(sk, chainId, assetId, balance, deltaAmount)
	if err != nil {
		t.Fatal(err)
	}
	proofStr := proof.String()
	proof2, err := ParseUnlockProofStr(proofStr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, res, "invalid proof")
}

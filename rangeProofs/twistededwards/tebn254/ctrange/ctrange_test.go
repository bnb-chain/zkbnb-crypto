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

package ctrange

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/hash/bn254/zmimc"
	"github.com/zecrey-labs/zecrey-crypto/util"
)

func TestVerify(t *testing.T) {
	b := int64(5)
	elapse := time.Now()
	_, proof, err := Prove(b, curve.G, curve.H)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("1:", time.Since(elapse))
	proofBytes := proof.Bytes()
	proof2, err := FromBytes(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	elapse = time.Now()
	res, err := proof2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("2:", time.Since(elapse))
	assert.Equal(t, true, res, "invalid proof")
}

func TestProve(t *testing.T) {
	h := zmimc.Hmimc
	h.Write(curve.H.X.Marshal())
	h.Write(curve.H.Y.Marshal())
	sum := h.Sum(nil)
	sumInt := new(big.Int).SetBytes(sum)
	fmt.Println(sumInt)
	var buf bytes.Buffer
	buf.Write(curve.H.X.Marshal())
	buf.Write(curve.H.Y.Marshal())
	z, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(z)
}

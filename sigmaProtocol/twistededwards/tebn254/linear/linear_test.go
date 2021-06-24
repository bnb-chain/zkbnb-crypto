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

package linear

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

func TestProveVerify(t *testing.T) {
	// n = 2 , m = 1
	inf := curve.ZeroPoint()
	b1 := new(big.Int).SetUint64(6)
	b2 := new(big.Int).SetInt64(-6)
	g := G
	xArr := []*big.Int{b1, b2}
	gArr := []*Point{g, g}
	uArr := []*Point{inf}
	zArr, UtArr := Prove(xArr, gArr, uArr)
	res := Verify(zArr, gArr, uArr, UtArr)
	assert.True(t, res, "should be true")
}

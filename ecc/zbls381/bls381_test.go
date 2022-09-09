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

package zbls381

import (
	"fmt"
	"math/big"
	"testing"
)

func TestG1ScalarMult(t *testing.T) {
	a := big.NewInt(2)
	b := big.NewInt(3)
	c := big.NewInt(8)
	A := G1ScalarBaseMul(a)
	B := G1ScalarMul(A, b)
	C := G1ScalarBaseMul(c)
	AB := G1Add(A, B)
	fmt.Println(AB.IsOnCurve())
	fmt.Println(AB.Equal(C))
}

func TestG1Neg(t *testing.T) {
	a := big.NewInt(39)
	A := G1ScalarBaseMul(a)
	ANeg := G1Neg(A)
	C := G1Add(A, ANeg)
	fmt.Println(C.IsInfinity())
}

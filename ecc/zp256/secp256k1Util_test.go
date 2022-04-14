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

package zp256

import (
	"fmt"
	"math/big"
	"testing"
)

func TestAdd(t *testing.T) {
	a := big.NewInt(2)
	b := big.NewInt(3)
	c := big.NewInt(8)
	A := ScalarBaseMul(a)
	B := ScalarMul(A, b)
	C := ScalarBaseMul(c)
	AB := Add(A, B)
	fmt.Println(AB.IsOnCurve())
	fmt.Println(Equal(AB, C))
	fmt.Println(ScalarBaseMul(big.NewInt(0)).IsZero())
}

func TestNeg(t *testing.T) {
	a := big.NewInt(100)
	A := ScalarBaseMul(a)
	ANeg := Neg(A)
	fmt.Println(A)
	fmt.Println(ANeg)
	C := Add(A, ANeg)
	fmt.Println(C)
	fmt.Println(C.IsZero())
}

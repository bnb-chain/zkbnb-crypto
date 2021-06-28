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

package std

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

func TestNeg(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness NegConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(r1cs.GetNbConstraints())
	r := curve.RandomValue()
	P := curve.ScalarBaseMul(r)
	PNeg := curve.Neg(P)

	witness.G.X.Assign("9671717474070082183213120605117400219616337014328744928644933853176787189663")
	witness.G.Y.Assign("16950150798460657717958625567821834550301663161624707787222815936182638968203")
	witness.P.X.Assign(P.X.String())
	witness.P.Y.Assign(P.Y.String())
	witness.N.X.Assign(PNeg.X.String())
	witness.N.Y.Assign(PNeg.Y.String())

	assert.SolvingSucceeded(r1cs, &witness)

}

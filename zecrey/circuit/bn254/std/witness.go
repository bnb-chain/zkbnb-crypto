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
	"errors"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

/*
	SetPointWitness set witness for Point
*/
func SetPointWitness(point *zecrey.Point) (witness Point, err error) {
	if point == nil {
		return witness, errors.New("[SetPointWitness] invalid point")
	}
	witness.X = point.X.String()
	witness.Y = point.Y.String()
	return witness, nil
}

/*
	SetPointWitness set witness for ElGamal Enc
*/
func SetElGamalEncWitness(encVal *zecrey.ElGamalEnc) (witness ElGamalEncConstraints, err error) {
	if encVal == nil {
		return witness, errors.New("[SetElGamalEncWitness] invalid Enc")
	}
	witness.CL, err = SetPointWitness(encVal.CL)
	if err != nil {
		return witness, err
	}
	witness.CR, err = SetPointWitness(encVal.CR)
	if err != nil {
		return witness, err
	}
	return witness, nil
}

func SetBoolWitness(isEnabled bool) Variable {
	var witness Variable
	if isEnabled {
		witness = 1
	} else {
		witness = 0
	}
	return witness
}

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

/*
	IsVariableEqual: check if two variables are equal, will force equal if isEnabled = false
*/
func IsVariableEqual(api API, isEnabled, i1, i2 Variable) {
	zero := 0
	i1 = api.Select(isEnabled, i1, zero)
	i2 = api.Select(isEnabled, i2, zero)
	api.AssertIsEqual(i1, i2)
}

/*
	IsPointEqual: check if two points are equal, will force equal if isEnabled = false
*/
func IsPointEqual(api API, isEnabled Variable, p1, p2 Point) {
	zero := 0
	p1.X = api.Select(isEnabled, p1.X, zero)
	p1.Y = api.Select(isEnabled, p1.Y, zero)
	p2.X = api.Select(isEnabled, p2.X, zero)
	p2.Y = api.Select(isEnabled, p2.Y, zero)
	api.AssertIsEqual(p1.X, p2.X)
	api.AssertIsEqual(p1.Y, p2.Y)
}

func GetPointNotEqualFlag(api API, a, b Point) Variable {
	return api.IsZero(api.And(api.IsZero(api.Sub(a.X, b.X)), api.IsZero(api.Sub(a.Y, b.Y))))
}

/*
	IsElGamalEncEqual: check if two ElGamalEnc are equal, will force equal if isEnabled = false
*/
func IsElGamalEncEqual(api API, isEnabled Variable, C1, C2 ElGamalEncConstraints) {
	IsPointEqual(api, isEnabled, C1.CL, C2.CL)
	IsPointEqual(api, isEnabled, C1.CR, C2.CR)
}

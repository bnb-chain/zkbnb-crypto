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
	IsVariableEqual: check if two variables are equal, will force equal if isEnabled = true
*/
func IsVariableEqual(cs *ConstraintSystem, isEnabled, i1, i2 Variable) {
	zero := cs.Constant(0)
	i1 = cs.Select(isEnabled, i1, zero)
	i2 = cs.Select(isEnabled, i2, zero)
	cs.AssertIsEqual(i1, i2)
}

/*
	IsPointEqual: check if two points are equal, will force equal if isEnabled = false
*/
func IsPointEqual(cs *ConstraintSystem, isEnabled Variable, p1, p2 Point) {
	zero := cs.Constant(0)
	p1.X = cs.Select(isEnabled, p1.X, zero)
	p1.Y = cs.Select(isEnabled, p1.Y, zero)
	p2.X = cs.Select(isEnabled, p2.X, zero)
	p2.Y = cs.Select(isEnabled, p2.Y, zero)
	cs.AssertIsEqual(p1.X, p2.X)
	cs.AssertIsEqual(p1.Y, p2.Y)
}

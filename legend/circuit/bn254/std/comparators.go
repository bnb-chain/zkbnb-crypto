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

import "github.com/consensys/gnark/frontend"

/*
	IsVariableEqual: check if two variables are equal, will force equal if isEnabled = false
*/
func IsVariableEqual(api API, isEnabled, i1, i2 Variable) {
	zero := 0
	i1 = api.Select(isEnabled, i1, zero)
	i2 = api.Select(isEnabled, i2, zero)
	api.AssertIsEqual(i1, i2)
}

func IsVariableLessOrEqual(api API, isEnabled, i1, i2 Variable) {
	zero := 0
	i1 = api.Select(isEnabled, i1, zero)
	i2 = api.Select(isEnabled, i2, zero)
	api.AssertIsLessOrEqual(i1, i2)
}

func IsVariableLess(api API, isEnabled, i1, i2 Variable) {
	zero := 0
	one := 1
	i1 = api.Select(isEnabled, i1, zero)
	i2 = api.Select(isEnabled, i2, one)
	api.AssertIsEqual(api.Cmp(i1, i2), -1)
}

func SelectPkBytes(api API, flag Variable, i1, i2 [32]Variable) [32]Variable {
	variables := [32]frontend.Variable{}
	for i := range i1 {
		variables[i] = api.Select(flag, i1[i], i2[i])
	}
	return variables
}

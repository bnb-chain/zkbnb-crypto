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
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"math/big"
)

type RegisterZnsTx struct {
	AccountName string
	PubKey      *eddsa.PublicKey
	L1Address   string
	AssetId     uint32
	AssetAmount *big.Int
}

type RegisterZnsTxConstraints struct {
	AccountName Variable
	PubKey      PublicKeyConstraints
	L1Address   Variable
	AssetId     Variable
	AssetAmount Variable
}

func EmptyRegisterZnsTxWitness() (witness RegisterZnsTxConstraints) {
	return RegisterZnsTxConstraints{
		AccountName: ZeroInt,
		PubKey:      EmptyPublicKeyWitness(),
		L1Address:   ZeroInt,
		AssetId:     ZeroInt,
		AssetAmount: ZeroInt,
	}
}

func SetRegisterZnsTxWitness(tx *RegisterZnsTx) (witness RegisterZnsTxConstraints) {
	witness = RegisterZnsTxConstraints{
		AccountName: tx.AccountName,
		PubKey:      SetPubKeyWitness(tx.PubKey),
		L1Address:   tx.L1Address,
		AssetId:     tx.AssetId,
		AssetAmount: tx.AssetAmount,
	}
	return witness
}

/*
	VerifyRegisterZnsTx:
	accounts order is:
	- FromAccount
		- Assets
			- AssetA
*/
func VerifyRegisterZnsTx(api API, flag Variable, tx RegisterZnsTxConstraints, accountsBefore, accountsAfter [NbAccountsPerTx]AccountConstraints) {
	// verify params
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetId, accountsAfter[0].AssetsInfo[0].AssetId)
}

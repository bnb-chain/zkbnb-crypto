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
	AccountName     *big.Int
	AccountNameHash []byte
	PubKey          *eddsa.PublicKey
	L1Address       string
}

type RegisterZnsTxConstraints struct {
	AccountName     Variable
	AccountNameHash Variable
	PubKey          PublicKeyConstraints
	L1Address       Variable
}

func EmptyRegisterZnsTxWitness() (witness RegisterZnsTxConstraints) {
	return RegisterZnsTxConstraints{
		AccountName:     ZeroInt,
		AccountNameHash: ZeroInt,
		PubKey:          EmptyPublicKeyWitness(),
		L1Address:       ZeroInt,
	}
}

func SetRegisterZnsTxWitness(tx *RegisterZnsTx) (witness RegisterZnsTxConstraints) {
	witness = RegisterZnsTxConstraints{
		AccountName:     tx.AccountName,
		AccountNameHash: tx.AccountNameHash,
		PubKey:          SetPubKeyWitness(tx.PubKey),
		L1Address:       tx.L1Address,
	}
	return witness
}

func VerifyRegisterZNSTx(api API, flag Variable, accountsBefore [NbAccountsPerTx]AccountConstraints) {
	CheckEmptyAccountNode(api, flag, accountsBefore[0])
}

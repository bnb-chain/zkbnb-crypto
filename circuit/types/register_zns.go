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

package types

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

type RegisterZnsTx struct {
	AccountIndex    int64
	AccountName     []byte
	AccountNameHash []byte
	PubKey          *eddsa.PublicKey
}

type RegisterZnsTxConstraints struct {
	AccountIndex    Variable
	AccountName     Variable
	AccountNameHash Variable
	PubKey          PublicKeyConstraints
}

func EmptyRegisterZnsTxWitness() (witness RegisterZnsTxConstraints) {
	return RegisterZnsTxConstraints{
		AccountIndex:    ZeroInt,
		AccountName:     ZeroInt,
		AccountNameHash: ZeroInt,
		PubKey:          EmptyPublicKeyWitness(),
	}
}

func SetRegisterZnsTxWitness(tx *RegisterZnsTx) (witness RegisterZnsTxConstraints) {
	witness = RegisterZnsTxConstraints{
		AccountIndex:    tx.AccountIndex,
		AccountName:     tx.AccountName,
		AccountNameHash: tx.AccountNameHash,
		PubKey:          SetPubKeyWitness(tx.PubKey),
	}
	return witness
}

func VerifyRegisterZNSTx(
	api API, flag Variable,
	tx RegisterZnsTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	pubData = CollectPubDataFromRegisterZNS(api, tx)
	CheckEmptyAccountNode(api, flag, accountsBefore[0])
	return pubData
}

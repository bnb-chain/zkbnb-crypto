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

type ChangePubKeyTx struct {
	AccountIndex int64
	L1Address    string
	PubKey       *eddsa.PublicKey
}

type ChangePubKeyTxConstraints struct {
	AccountIndex Variable
	L1Address    Variable
	PubKey       PublicKeyConstraints
}

func EmptyChangePubKeyTxWitness() (witness ChangePubKeyTxConstraints) {
	return ChangePubKeyTxConstraints{
		AccountIndex: ZeroInt,
		L1Address:    ZeroInt,
		PubKey:       EmptyPublicKeyWitness(),
	}
}

func SetChangePubKeyTxWitness(tx *ChangePubKeyTx) (witness ChangePubKeyTxConstraints) {
	witness = ChangePubKeyTxConstraints{
		AccountIndex: tx.AccountIndex,
		L1Address:    tx.L1Address,
		PubKey:       SetPubKeyWitness(tx.PubKey),
	}
	return witness
}

func VerifyChangePubKeyTx(
	api API, flag Variable,
	tx ChangePubKeyTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	pubData = CollectPubDataFromChangePubKey(api, tx)
	CheckEmptyAccountNode(api, flag, accountsBefore[0])
	return pubData
}

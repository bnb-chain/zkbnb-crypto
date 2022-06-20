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

package schnorr

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"gotest.tools/assert"
	"math/big"
	"testing"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

// pk = g^{sk}
func TestProveVerify(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	g := curve.G
	z, A := Prove(sk, g, pk)
	res := Verify(z, A, pk, g)
	assert.Equal(t, true, res)
}

func TestAssign(t *testing.T) {
	z, _ := new(big.Int).SetString("56457306562257122565246154685424300206626160564298072980723270873916373234", 10)
	//c, _ := new(big.Int).SetString("12570305820242045194614329830538401576680239494304591206526835130365207477516", 10)
	G := &Point{
		X: *new(fr.Element).SetString("9671717474070082183213120605117400219616337014328744928644933853176787189663"),
		Y: *new(fr.Element).SetString("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
	}
	A := &Point{
		X: *new(fr.Element).SetString("1805826214268140062109789454888545380426720994127895546120718277293486808528"),
		Y: *new(fr.Element).SetString("1992424522915255363820795818666870149715470888958691910097484002003697548446"),
	}
	pk := &Point{
		X: *new(fr.Element).SetString("20062244510347148272446781100879286480638585431533684331180269070589632792928"),
		Y: *new(fr.Element).SetString("1270552922097600254906946530389401056931473037205902458907582592439177824778"),
	}
	res := Verify(z, A, pk, G)
	fmt.Println(res)

}

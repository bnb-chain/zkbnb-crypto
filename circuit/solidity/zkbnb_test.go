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

package solidity

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
	"github.com/consensys/gnark/backend"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/bnb-chain/zkbnb-crypto/circuit"
)

var optionalBlockSizes = flag.String("blocksizes", "1,10", "block size that will be used for proof generation and verification")

func TestCompileCircuit(t *testing.T) {
	differentBlockSizes := optionalBlockSizesInt()
	gasAssetIds := []int64{0, 1}
	gasAccountIndex := int64(1)
	for i := 0; i < len(differentBlockSizes); i++ {
		bN := 16
		var blockConstraints circuit.BlockConstraints
		blockConstraints.TxsCount = differentBlockSizes[i]
		blockConstraints.Txs = make([]circuit.TxConstraints, blockConstraints.TxsCount)
		for i := 0; i < blockConstraints.TxsCount; i++ {
			blockConstraints.Txs[i] = circuit.GetZeroTxConstraint()
		}
		blockConstraints.GasAssetIds = gasAssetIds
		blockConstraints.GasAccountIndex = gasAccountIndex
		blockConstraints.GKRs.AllocateGKRCircuit(bN)
		blockConstraints.Gas = circuit.GetZeroGasConstraints(gasAssetIds)
		oR1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &blockConstraints, frontend.IgnoreUnconstrainedInputs(), frontend.WithGkrBN(bN))
		if err != nil {
			panic(err)
		}
		fmt.Printf("Number of constraints: %d\n", oR1cs.GetNbConstraints())
	}
}

func TestExportSol(t *testing.T) {
	exportSol(optionalBlockSizesInt())
}

func TestExportSolSmall(t *testing.T) {
	exportSol([]int{1})
}

func exportSol(differentBlockSizes []int) {
	gasAssetIds := []int64{0, 1}
	gasAccountIndex := int64(1)
	sessionName := "zkbnb"

	for i := 0; i < len(differentBlockSizes); i++ {
		var blockConstraints circuit.BlockConstraints
		bN := 13
		blockConstraints.TxsCount = differentBlockSizes[i]
		blockConstraints.Txs = make([]circuit.TxConstraints, blockConstraints.TxsCount)
		for i := 0; i < blockConstraints.TxsCount; i++ {
			blockConstraints.Txs[i] = circuit.GetZeroTxConstraint()
		}
		blockConstraints.GasAssetIds = gasAssetIds
		blockConstraints.GasAccountIndex = gasAccountIndex
		blockConstraints.Gas = circuit.GetZeroGasConstraints(gasAssetIds)
		blockConstraints.GKRs.AllocateGKRCircuit(bN)
		oR1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &blockConstraints, frontend.IgnoreUnconstrainedInputs(), frontend.WithGkrBN(bN))
		fmt.Printf("Constraints num=%v\n", oR1cs.GetNbConstraints())
		if err != nil {
			panic(err)
		}

		// pk, vk, err := groth16.Setup(oR1cs)
		internal, secret, public := oR1cs.GetNbVariables()
		fmt.Printf("Variables num=%v\n", internal+secret+public)

		witnessJson := "{\"BlockNumber\":1,\"CreatedAt\":1679315078173,\"OldStateRoot\":\"KwQ5wkdvKjoDoV1rJvDH1NvFpmApLrZgnWhEQIQ7MdA=\",\"NewStateRoot\":\"IcXB8kWYivltKTzI1FWgtA+DFfN9rTcsF2il/4woXK4=\",\"BlockCommitment\":\"dCbPf9N4NU8TkmEBO1CKawXYHaIKaRZNweA6/ycc8jQ=\",\"Txs\":[{\"TxType\":1,\"RegisterZnsTxInfo\":{\"AccountIndex\":0,\"AccountName\":\"dHJlYXN1cnkAAAAAAAAAAAAAAAA=\",\"AccountNameHash\":\"Cw2fyV8d2o4UA7yShJMyAao4lipYvvL7Mz1ZqjdX4hM=\",\"PubKey\":{\"A\":{\"X\":\"14484360187115515278733210269992718701173976757350893382182383105149037650359\",\"Y\":\"11154855370701960708009161922318992281429653121622874600953197233529120340220\"}}},\"DepositTxInfo\":null,\"DepositNftTxInfo\":null,\"TransferTxInfo\":null,\"CreateCollectionTxInfo\":null,\"MintNftTxInfo\":null,\"TransferNftTxInfo\":null,\"AtomicMatchTxInfo\":null,\"CancelOfferTxInfo\":null,\"WithdrawTxInfo\":null,\"WithdrawNftTxInfo\":null,\"FullExitTxInfo\":null,\"FullExitNftTxInfo\":null,\"Nonce\":-1,\"ExpiredAt\":0,\"Signature\":{\"R\":{\"X\":0,\"Y\":0},\"S\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]},\"AccountRootBefore\":\"CxNyCfCbSdC/AcQNk5XT7wONiH7DHHF5CH8RYbDKGKM=\",\"AccountsInfoBefore\":[{\"AccountIndex\":0,\"AccountNameHash\":\"\",\"AccountPk\":{\"A\":{\"X\":0,\"Y\":0}},\"Nonce\":0,\"CollectionNonce\":0,\"AssetRoot\":\"GtZCjLWJ+BiXQINqtGjcwIx8EEpKtA9NRovgZQek+jk=\",\"AssetsInfo\":[{\"AssetId\":65535,\"Balance\":0,\"OfferCanceledOrFinalized\":0},{\"AssetId\":65535,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]},{\"AccountIndex\":4294967295,\"AccountNameHash\":\"\",\"AccountPk\":{\"A\":{\"X\":0,\"Y\":0}},\"Nonce\":0,\"CollectionNonce\":0,\"AssetRoot\":\"GtZCjLWJ+BiXQINqtGjcwIx8EEpKtA9NRovgZQek+jk=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0},{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]},{\"AccountIndex\":4294967295,\"AccountNameHash\":\"\",\"AccountPk\":{\"A\":{\"X\":0,\"Y\":0}},\"Nonce\":0,\"CollectionNonce\":0,\"AssetRoot\":\"GtZCjLWJ+BiXQINqtGjcwIx8EEpKtA9NRovgZQek+jk=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0},{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]},{\"AccountIndex\":4294967295,\"AccountNameHash\":\"\",\"AccountPk\":{\"A\":{\"X\":0,\"Y\":0}},\"Nonce\":0,\"CollectionNonce\":0,\"AssetRoot\":\"GtZCjLWJ+BiXQINqtGjcwIx8EEpKtA9NRovgZQek+jk=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0},{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]}],\"NftRootBefore\":\"LIAOYW0xqb7Jba42LaF483IUkfxGdUFCTmT5CULglEo=\",\"NftBefore\":{\"NftIndex\":1099511627775,\"NftContentHash\":\"AA==\",\"CreatorAccountIndex\":0,\"OwnerAccountIndex\":0,\"CreatorTreasuryRate\":0,\"CollectionId\":0},\"StateRootBefore\":\"KwQ5wkdvKjoDoV1rJvDH1NvFpmApLrZgnWhEQIQ7MdA=\",\"MerkleProofsAccountAssetsBefore\":[[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"FTJM/63uEvv6D+qsIAMsa4bpohmn86uvfN59A/+H0f8=\",\"ILZsuVI4UGvnGQPwjXvgepL1pLoTvF1q7wYki78PGRM=\",\"Cafa2e8frf3AIeeBmaJANpSvfHf80oYDHkpMVVi2U5Q=\",\"Gl+riWk8KrVAwbcRKCYl9kZCNU0D0jCM1Q8/X3h74R4=\",\"I1rLGfDVy5zxVErn7amY1IjmnSnWn1O3/GLrifdxB3M=\",\"GqHECZ6+A/k6vByQTyCFSNAlBMGZ7ycRoY7jQQlkbhk=\",\"IbvTWBAn8d4PKNj2MmlXdwCG487mUp4JocrgoxfO+48=\",\"AB887XbshntIfM5vcB108u2vK6jvop8h73U7XfWts4Y=\",\"AX40KYXth01MNR71cBWfA2L+E86a+guDGnNQSV54sw4=\",\"HlfEvtfn6KBvS9IJAb58Q5yKC8vb0Hho6ILjVI0m7Yo=\",\"H4cEBTQO+svzZ87ZgA1fYRSMhKg5RKDsDK987tMG9yE=\",\"J+mylRlVQq8zoLQiCM2piW7TQzL8TQqZElp1I+FUPEA=\",\"CX9itoG8P1dbOOupeDHEUp6b6cMtN2t6ysW6qbs0Avk=\",\"DBT6cwL/8x/zrFBdXPZDny/627LG6s60Hzeo9kq71rs=\",\"Bz+NfP5WBA3hHqrEJcFy4OBOJwJfJ8KQq6FGk6WfaHs=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"FTJM/63uEvv6D+qsIAMsa4bpohmn86uvfN59A/+H0f8=\",\"ILZsuVI4UGvnGQPwjXvgepL1pLoTvF1q7wYki78PGRM=\",\"Cafa2e8frf3AIeeBmaJANpSvfHf80oYDHkpMVVi2U5Q=\",\"Gl+riWk8KrVAwbcRKCYl9kZCNU0D0jCM1Q8/X3h74R4=\",\"I1rLGfDVy5zxVErn7amY1IjmnSnWn1O3/GLrifdxB3M=\",\"GqHECZ6+A/k6vByQTyCFSNAlBMGZ7ycRoY7jQQlkbhk=\",\"IbvTWBAn8d4PKNj2MmlXdwCG487mUp4JocrgoxfO+48=\",\"AB887XbshntIfM5vcB108u2vK6jvop8h73U7XfWts4Y=\",\"AX40KYXth01MNR71cBWfA2L+E86a+guDGnNQSV54sw4=\",\"HlfEvtfn6KBvS9IJAb58Q5yKC8vb0Hho6ILjVI0m7Yo=\",\"H4cEBTQO+svzZ87ZgA1fYRSMhKg5RKDsDK987tMG9yE=\",\"J+mylRlVQq8zoLQiCM2piW7TQzL8TQqZElp1I+FUPEA=\",\"CX9itoG8P1dbOOupeDHEUp6b6cMtN2t6ysW6qbs0Avk=\",\"DBT6cwL/8x/zrFBdXPZDny/627LG6s60Hzeo9kq71rs=\",\"Bz+NfP5WBA3hHqrEJcFy4OBOJwJfJ8KQq6FGk6WfaHs=\"]],[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"FTJM/63uEvv6D+qsIAMsa4bpohmn86uvfN59A/+H0f8=\",\"ILZsuVI4UGvnGQPwjXvgepL1pLoTvF1q7wYki78PGRM=\",\"Cafa2e8frf3AIeeBmaJANpSvfHf80oYDHkpMVVi2U5Q=\",\"Gl+riWk8KrVAwbcRKCYl9kZCNU0D0jCM1Q8/X3h74R4=\",\"I1rLGfDVy5zxVErn7amY1IjmnSnWn1O3/GLrifdxB3M=\",\"GqHECZ6+A/k6vByQTyCFSNAlBMGZ7ycRoY7jQQlkbhk=\",\"IbvTWBAn8d4PKNj2MmlXdwCG487mUp4JocrgoxfO+48=\",\"AB887XbshntIfM5vcB108u2vK6jvop8h73U7XfWts4Y=\",\"AX40KYXth01MNR71cBWfA2L+E86a+guDGnNQSV54sw4=\",\"HlfEvtfn6KBvS9IJAb58Q5yKC8vb0Hho6ILjVI0m7Yo=\",\"H4cEBTQO+svzZ87ZgA1fYRSMhKg5RKDsDK987tMG9yE=\",\"J+mylRlVQq8zoLQiCM2piW7TQzL8TQqZElp1I+FUPEA=\",\"CX9itoG8P1dbOOupeDHEUp6b6cMtN2t6ysW6qbs0Avk=\",\"DBT6cwL/8x/zrFBdXPZDny/627LG6s60Hzeo9kq71rs=\",\"Bz+NfP5WBA3hHqrEJcFy4OBOJwJfJ8KQq6FGk6WfaHs=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"FTJM/63uEvv6D+qsIAMsa4bpohmn86uvfN59A/+H0f8=\",\"ILZsuVI4UGvnGQPwjXvgepL1pLoTvF1q7wYki78PGRM=\",\"Cafa2e8frf3AIeeBmaJANpSvfHf80oYDHkpMVVi2U5Q=\",\"Gl+riWk8KrVAwbcRKCYl9kZCNU0D0jCM1Q8/X3h74R4=\",\"I1rLGfDVy5zxVErn7amY1IjmnSnWn1O3/GLrifdxB3M=\",\"GqHECZ6+A/k6vByQTyCFSNAlBMGZ7ycRoY7jQQlkbhk=\",\"IbvTWBAn8d4PKNj2MmlXdwCG487mUp4JocrgoxfO+48=\",\"AB887XbshntIfM5vcB108u2vK6jvop8h73U7XfWts4Y=\",\"AX40KYXth01MNR71cBWfA2L+E86a+guDGnNQSV54sw4=\",\"HlfEvtfn6KBvS9IJAb58Q5yKC8vb0Hho6ILjVI0m7Yo=\",\"H4cEBTQO+svzZ87ZgA1fYRSMhKg5RKDsDK987tMG9yE=\",\"J+mylRlVQq8zoLQiCM2piW7TQzL8TQqZElp1I+FUPEA=\",\"CX9itoG8P1dbOOupeDHEUp6b6cMtN2t6ysW6qbs0Avk=\",\"DBT6cwL/8x/zrFBdXPZDny/627LG6s60Hzeo9kq71rs=\",\"Bz+NfP5WBA3hHqrEJcFy4OBOJwJfJ8KQq6FGk6WfaHs=\"]],[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"FTJM/63uEvv6D+qsIAMsa4bpohmn86uvfN59A/+H0f8=\",\"ILZsuVI4UGvnGQPwjXvgepL1pLoTvF1q7wYki78PGRM=\",\"Cafa2e8frf3AIeeBmaJANpSvfHf80oYDHkpMVVi2U5Q=\",\"Gl+riWk8KrVAwbcRKCYl9kZCNU0D0jCM1Q8/X3h74R4=\",\"I1rLGfDVy5zxVErn7amY1IjmnSnWn1O3/GLrifdxB3M=\",\"GqHECZ6+A/k6vByQTyCFSNAlBMGZ7ycRoY7jQQlkbhk=\",\"IbvTWBAn8d4PKNj2MmlXdwCG487mUp4JocrgoxfO+48=\",\"AB887XbshntIfM5vcB108u2vK6jvop8h73U7XfWts4Y=\",\"AX40KYXth01MNR71cBWfA2L+E86a+guDGnNQSV54sw4=\",\"HlfEvtfn6KBvS9IJAb58Q5yKC8vb0Hho6ILjVI0m7Yo=\",\"H4cEBTQO+svzZ87ZgA1fYRSMhKg5RKDsDK987tMG9yE=\",\"J+mylRlVQq8zoLQiCM2piW7TQzL8TQqZElp1I+FUPEA=\",\"CX9itoG8P1dbOOupeDHEUp6b6cMtN2t6ysW6qbs0Avk=\",\"DBT6cwL/8x/zrFBdXPZDny/627LG6s60Hzeo9kq71rs=\",\"Bz+NfP5WBA3hHqrEJcFy4OBOJwJfJ8KQq6FGk6WfaHs=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"FTJM/63uEvv6D+qsIAMsa4bpohmn86uvfN59A/+H0f8=\",\"ILZsuVI4UGvnGQPwjXvgepL1pLoTvF1q7wYki78PGRM=\",\"Cafa2e8frf3AIeeBmaJANpSvfHf80oYDHkpMVVi2U5Q=\",\"Gl+riWk8KrVAwbcRKCYl9kZCNU0D0jCM1Q8/X3h74R4=\",\"I1rLGfDVy5zxVErn7amY1IjmnSnWn1O3/GLrifdxB3M=\",\"GqHECZ6+A/k6vByQTyCFSNAlBMGZ7ycRoY7jQQlkbhk=\",\"IbvTWBAn8d4PKNj2MmlXdwCG487mUp4JocrgoxfO+48=\",\"AB887XbshntIfM5vcB108u2vK6jvop8h73U7XfWts4Y=\",\"AX40KYXth01MNR71cBWfA2L+E86a+guDGnNQSV54sw4=\",\"HlfEvtfn6KBvS9IJAb58Q5yKC8vb0Hho6ILjVI0m7Yo=\",\"H4cEBTQO+svzZ87ZgA1fYRSMhKg5RKDsDK987tMG9yE=\",\"J+mylRlVQq8zoLQiCM2piW7TQzL8TQqZElp1I+FUPEA=\",\"CX9itoG8P1dbOOupeDHEUp6b6cMtN2t6ysW6qbs0Avk=\",\"DBT6cwL/8x/zrFBdXPZDny/627LG6s60Hzeo9kq71rs=\",\"Bz+NfP5WBA3hHqrEJcFy4OBOJwJfJ8KQq6FGk6WfaHs=\"]],[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"FTJM/63uEvv6D+qsIAMsa4bpohmn86uvfN59A/+H0f8=\",\"ILZsuVI4UGvnGQPwjXvgepL1pLoTvF1q7wYki78PGRM=\",\"Cafa2e8frf3AIeeBmaJANpSvfHf80oYDHkpMVVi2U5Q=\",\"Gl+riWk8KrVAwbcRKCYl9kZCNU0D0jCM1Q8/X3h74R4=\",\"I1rLGfDVy5zxVErn7amY1IjmnSnWn1O3/GLrifdxB3M=\",\"GqHECZ6+A/k6vByQTyCFSNAlBMGZ7ycRoY7jQQlkbhk=\",\"IbvTWBAn8d4PKNj2MmlXdwCG487mUp4JocrgoxfO+48=\",\"AB887XbshntIfM5vcB108u2vK6jvop8h73U7XfWts4Y=\",\"AX40KYXth01MNR71cBWfA2L+E86a+guDGnNQSV54sw4=\",\"HlfEvtfn6KBvS9IJAb58Q5yKC8vb0Hho6ILjVI0m7Yo=\",\"H4cEBTQO+svzZ87ZgA1fYRSMhKg5RKDsDK987tMG9yE=\",\"J+mylRlVQq8zoLQiCM2piW7TQzL8TQqZElp1I+FUPEA=\",\"CX9itoG8P1dbOOupeDHEUp6b6cMtN2t6ysW6qbs0Avk=\",\"DBT6cwL/8x/zrFBdXPZDny/627LG6s60Hzeo9kq71rs=\",\"Bz+NfP5WBA3hHqrEJcFy4OBOJwJfJ8KQq6FGk6WfaHs=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"FTJM/63uEvv6D+qsIAMsa4bpohmn86uvfN59A/+H0f8=\",\"ILZsuVI4UGvnGQPwjXvgepL1pLoTvF1q7wYki78PGRM=\",\"Cafa2e8frf3AIeeBmaJANpSvfHf80oYDHkpMVVi2U5Q=\",\"Gl+riWk8KrVAwbcRKCYl9kZCNU0D0jCM1Q8/X3h74R4=\",\"I1rLGfDVy5zxVErn7amY1IjmnSnWn1O3/GLrifdxB3M=\",\"GqHECZ6+A/k6vByQTyCFSNAlBMGZ7ycRoY7jQQlkbhk=\",\"IbvTWBAn8d4PKNj2MmlXdwCG487mUp4JocrgoxfO+48=\",\"AB887XbshntIfM5vcB108u2vK6jvop8h73U7XfWts4Y=\",\"AX40KYXth01MNR71cBWfA2L+E86a+guDGnNQSV54sw4=\",\"HlfEvtfn6KBvS9IJAb58Q5yKC8vb0Hho6ILjVI0m7Yo=\",\"H4cEBTQO+svzZ87ZgA1fYRSMhKg5RKDsDK987tMG9yE=\",\"J+mylRlVQq8zoLQiCM2piW7TQzL8TQqZElp1I+FUPEA=\",\"CX9itoG8P1dbOOupeDHEUp6b6cMtN2t6ysW6qbs0Avk=\",\"DBT6cwL/8x/zrFBdXPZDny/627LG6s60Hzeo9kq71rs=\",\"Bz+NfP5WBA3hHqrEJcFy4OBOJwJfJ8KQq6FGk6WfaHs=\"]]],\"MerkleProofsAccountBefore\":[[\"DKmzWq7lJ798xqVmFmLmBgfnOP6EMKa8rQegJP4GlYE=\",\"BbM7CeFco1bnoP+EXzWqEq97pm0AIUlKGb0AOsi24Xs=\",\"CO/3B1OR8+ExBAmZLdvq+y7JOZytdU/T5WIH9L5W/8M=\",\"AfYygkZh7jvClhV/00a8QRd0jHBazPHgL7IkiCnNON0=\",\"HZIpJ3oov/YqtpeqBZYz2cVvL9MHc+Hxic4oAs2azko=\",\"EPalwaWTBPDKMbgC2Olu9DAVCy4FohCuQtnZSx83c80=\",\"GBoLqjeyqmjEd1jNl07ShpZ9mjvGNq1Cr8e/n37tfN0=\",\"EsbuF6ELNG6W2NUk4unXV+J7mVucI5tf6EBL0bY3f9s=\",\"J8ZpV92DsmO8SoHKgd38Tzm8GSu+FciKWwMBoLacUNc=\",\"JARv5hBXEJ0D33/Vp60Uqsbbop+L5W/orbPoVYj0U7g=\",\"FyCyMeQig6KNayj5e1BGnb+idTTHpBms+t62PbWtW2w=\",\"DiTYYj8tDURSNaiXdgj2HZjM9kxsuFzzMl1iaJDBkqQ=\",\"AAQlYtym1SCx+ZXUfQneKaQ0s4EiHM3xA0RDClhONhE=\",\"GNzh6J8ma0g5PYwDN82LPg0QL5c23bSlKRMs3UMx67c=\",\"CasXSG+Fl7d7LqrhibDU70BcBqgxx4y7KV0GTG4F86A=\",\"KUNhAnPJ1RDl562V3f983aEIjyg79Z+w7UZAAWVGE8s=\",\"GI6i92i1TyiyDxElx9mCODGz5kq60rb1qBx9nuNoed0=\",\"GZTU6MidGuVnHNshNe7ez3ic9XG21Ui8kVmLMiSRi5U=\",\"AirfELhjjvRRDU0r7Lyg4SBvPoLSki+9T03NeKZjMTo=\",\"AWH4FKi97BhCmO0MgoJE5A/Tb7ViFVtC/R1f5Oli5F4=\",\"AvKirFoKFQOx2urE22lFDF5dGMm8olKDuH1hvwqJg64=\",\"JWQHHBP9qT2fshisyfsUqrdpaintuFLbyopn4Lm7xfs=\",\"AK0SN8q8Lni2yOx5EakInoCNhEAlshXBDdRf+zyTbp8=\",\"KNO7USWpXQjqN0UCTv6pTghdkUG1AohQFb5xAZa5xYA=\",\"FNVNP8BekY5FHbEwAr/ChSx+1muq82J/E5noaNqpBhM=\",\"K+Yv3RkQFwAse9fxjwAgULAn8DQKeC6tILbFrhlDVB0=\",\"GqyqSHuHXtExnBxLEegrPnMJB6C7XDFW3Y3oxdN6L+o=\",\"IjLZ/0ZBr1FD3oAga46CmRfvSs5mT+k7uYQTCDfMpEs=\",\"Jq0ieJa3PiNW8FlYDQxKG6htWQey9IdD1DK84cJSzJ8=\",\"F9Ruy0tnL8XatF5yc29SNjMvl9RISPSf7oYcibYqITk=\",\"CV12Io5iYamsvVeYAjyqfQzUp53cn4JbfpBEIr+0X1Q=\",\"GvI1Vd5oAQ/bqng06pfQ6a/CXrrmTrE+nb6lXKP29OM=\"],[\"DKmzWq7lJ798xqVmFmLmBgfnOP6EMKa8rQegJP4GlYE=\",\"BbM7CeFco1bnoP+EXzWqEq97pm0AIUlKGb0AOsi24Xs=\",\"CO/3B1OR8+ExBAmZLdvq+y7JOZytdU/T5WIH9L5W/8M=\",\"AfYygkZh7jvClhV/00a8QRd0jHBazPHgL7IkiCnNON0=\",\"HZIpJ3oov/YqtpeqBZYz2cVvL9MHc+Hxic4oAs2azko=\",\"EPalwaWTBPDKMbgC2Olu9DAVCy4FohCuQtnZSx83c80=\",\"GBoLqjeyqmjEd1jNl07ShpZ9mjvGNq1Cr8e/n37tfN0=\",\"EsbuF6ELNG6W2NUk4unXV+J7mVucI5tf6EBL0bY3f9s=\",\"J8ZpV92DsmO8SoHKgd38Tzm8GSu+FciKWwMBoLacUNc=\",\"JARv5hBXEJ0D33/Vp60Uqsbbop+L5W/orbPoVYj0U7g=\",\"FyCyMeQig6KNayj5e1BGnb+idTTHpBms+t62PbWtW2w=\",\"DiTYYj8tDURSNaiXdgj2HZjM9kxsuFzzMl1iaJDBkqQ=\",\"AAQlYtym1SCx+ZXUfQneKaQ0s4EiHM3xA0RDClhONhE=\",\"GNzh6J8ma0g5PYwDN82LPg0QL5c23bSlKRMs3UMx67c=\",\"CasXSG+Fl7d7LqrhibDU70BcBqgxx4y7KV0GTG4F86A=\",\"KUNhAnPJ1RDl562V3f983aEIjyg79Z+w7UZAAWVGE8s=\",\"GI6i92i1TyiyDxElx9mCODGz5kq60rb1qBx9nuNoed0=\",\"GZTU6MidGuVnHNshNe7ez3ic9XG21Ui8kVmLMiSRi5U=\",\"AirfELhjjvRRDU0r7Lyg4SBvPoLSki+9T03NeKZjMTo=\",\"AWH4FKi97BhCmO0MgoJE5A/Tb7ViFVtC/R1f5Oli5F4=\",\"AvKirFoKFQOx2urE22lFDF5dGMm8olKDuH1hvwqJg64=\",\"JWQHHBP9qT2fshisyfsUqrdpaintuFLbyopn4Lm7xfs=\",\"AK0SN8q8Lni2yOx5EakInoCNhEAlshXBDdRf+zyTbp8=\",\"KNO7USWpXQjqN0UCTv6pTghdkUG1AohQFb5xAZa5xYA=\",\"FNVNP8BekY5FHbEwAr/ChSx+1muq82J/E5noaNqpBhM=\",\"K+Yv3RkQFwAse9fxjwAgULAn8DQKeC6tILbFrhlDVB0=\",\"GqyqSHuHXtExnBxLEegrPnMJB6C7XDFW3Y3oxdN6L+o=\",\"IjLZ/0ZBr1FD3oAga46CmRfvSs5mT+k7uYQTCDfMpEs=\",\"Jq0ieJa3PiNW8FlYDQxKG6htWQey9IdD1DK84cJSzJ8=\",\"F9Ruy0tnL8XatF5yc29SNjMvl9RISPSf7oYcibYqITk=\",\"CV12Io5iYamsvVeYAjyqfQzUp53cn4JbfpBEIr+0X1Q=\",\"IPTZtl4GtExbB+rE2ocCQ3+byI5WKWU2HnuMqsUVyls=\"],[\"DKmzWq7lJ798xqVmFmLmBgfnOP6EMKa8rQegJP4GlYE=\",\"BbM7CeFco1bnoP+EXzWqEq97pm0AIUlKGb0AOsi24Xs=\",\"CO/3B1OR8+ExBAmZLdvq+y7JOZytdU/T5WIH9L5W/8M=\",\"AfYygkZh7jvClhV/00a8QRd0jHBazPHgL7IkiCnNON0=\",\"HZIpJ3oov/YqtpeqBZYz2cVvL9MHc+Hxic4oAs2azko=\",\"EPalwaWTBPDKMbgC2Olu9DAVCy4FohCuQtnZSx83c80=\",\"GBoLqjeyqmjEd1jNl07ShpZ9mjvGNq1Cr8e/n37tfN0=\",\"EsbuF6ELNG6W2NUk4unXV+J7mVucI5tf6EBL0bY3f9s=\",\"J8ZpV92DsmO8SoHKgd38Tzm8GSu+FciKWwMBoLacUNc=\",\"JARv5hBXEJ0D33/Vp60Uqsbbop+L5W/orbPoVYj0U7g=\",\"FyCyMeQig6KNayj5e1BGnb+idTTHpBms+t62PbWtW2w=\",\"DiTYYj8tDURSNaiXdgj2HZjM9kxsuFzzMl1iaJDBkqQ=\",\"AAQlYtym1SCx+ZXUfQneKaQ0s4EiHM3xA0RDClhONhE=\",\"GNzh6J8ma0g5PYwDN82LPg0QL5c23bSlKRMs3UMx67c=\",\"CasXSG+Fl7d7LqrhibDU70BcBqgxx4y7KV0GTG4F86A=\",\"KUNhAnPJ1RDl562V3f983aEIjyg79Z+w7UZAAWVGE8s=\",\"GI6i92i1TyiyDxElx9mCODGz5kq60rb1qBx9nuNoed0=\",\"GZTU6MidGuVnHNshNe7ez3ic9XG21Ui8kVmLMiSRi5U=\",\"AirfELhjjvRRDU0r7Lyg4SBvPoLSki+9T03NeKZjMTo=\",\"AWH4FKi97BhCmO0MgoJE5A/Tb7ViFVtC/R1f5Oli5F4=\",\"AvKirFoKFQOx2urE22lFDF5dGMm8olKDuH1hvwqJg64=\",\"JWQHHBP9qT2fshisyfsUqrdpaintuFLbyopn4Lm7xfs=\",\"AK0SN8q8Lni2yOx5EakInoCNhEAlshXBDdRf+zyTbp8=\",\"KNO7USWpXQjqN0UCTv6pTghdkUG1AohQFb5xAZa5xYA=\",\"FNVNP8BekY5FHbEwAr/ChSx+1muq82J/E5noaNqpBhM=\",\"K+Yv3RkQFwAse9fxjwAgULAn8DQKeC6tILbFrhlDVB0=\",\"GqyqSHuHXtExnBxLEegrPnMJB6C7XDFW3Y3oxdN6L+o=\",\"IjLZ/0ZBr1FD3oAga46CmRfvSs5mT+k7uYQTCDfMpEs=\",\"Jq0ieJa3PiNW8FlYDQxKG6htWQey9IdD1DK84cJSzJ8=\",\"F9Ruy0tnL8XatF5yc29SNjMvl9RISPSf7oYcibYqITk=\",\"CV12Io5iYamsvVeYAjyqfQzUp53cn4JbfpBEIr+0X1Q=\",\"IPTZtl4GtExbB+rE2ocCQ3+byI5WKWU2HnuMqsUVyls=\"],[\"DKmzWq7lJ798xqVmFmLmBgfnOP6EMKa8rQegJP4GlYE=\",\"BbM7CeFco1bnoP+EXzWqEq97pm0AIUlKGb0AOsi24Xs=\",\"CO/3B1OR8+ExBAmZLdvq+y7JOZytdU/T5WIH9L5W/8M=\",\"AfYygkZh7jvClhV/00a8QRd0jHBazPHgL7IkiCnNON0=\",\"HZIpJ3oov/YqtpeqBZYz2cVvL9MHc+Hxic4oAs2azko=\",\"EPalwaWTBPDKMbgC2Olu9DAVCy4FohCuQtnZSx83c80=\",\"GBoLqjeyqmjEd1jNl07ShpZ9mjvGNq1Cr8e/n37tfN0=\",\"EsbuF6ELNG6W2NUk4unXV+J7mVucI5tf6EBL0bY3f9s=\",\"J8ZpV92DsmO8SoHKgd38Tzm8GSu+FciKWwMBoLacUNc=\",\"JARv5hBXEJ0D33/Vp60Uqsbbop+L5W/orbPoVYj0U7g=\",\"FyCyMeQig6KNayj5e1BGnb+idTTHpBms+t62PbWtW2w=\",\"DiTYYj8tDURSNaiXdgj2HZjM9kxsuFzzMl1iaJDBkqQ=\",\"AAQlYtym1SCx+ZXUfQneKaQ0s4EiHM3xA0RDClhONhE=\",\"GNzh6J8ma0g5PYwDN82LPg0QL5c23bSlKRMs3UMx67c=\",\"CasXSG+Fl7d7LqrhibDU70BcBqgxx4y7KV0GTG4F86A=\",\"KUNhAnPJ1RDl562V3f983aEIjyg79Z+w7UZAAWVGE8s=\",\"GI6i92i1TyiyDxElx9mCODGz5kq60rb1qBx9nuNoed0=\",\"GZTU6MidGuVnHNshNe7ez3ic9XG21Ui8kVmLMiSRi5U=\",\"AirfELhjjvRRDU0r7Lyg4SBvPoLSki+9T03NeKZjMTo=\",\"AWH4FKi97BhCmO0MgoJE5A/Tb7ViFVtC/R1f5Oli5F4=\",\"AvKirFoKFQOx2urE22lFDF5dGMm8olKDuH1hvwqJg64=\",\"JWQHHBP9qT2fshisyfsUqrdpaintuFLbyopn4Lm7xfs=\",\"AK0SN8q8Lni2yOx5EakInoCNhEAlshXBDdRf+zyTbp8=\",\"KNO7USWpXQjqN0UCTv6pTghdkUG1AohQFb5xAZa5xYA=\",\"FNVNP8BekY5FHbEwAr/ChSx+1muq82J/E5noaNqpBhM=\",\"K+Yv3RkQFwAse9fxjwAgULAn8DQKeC6tILbFrhlDVB0=\",\"GqyqSHuHXtExnBxLEegrPnMJB6C7XDFW3Y3oxdN6L+o=\",\"IjLZ/0ZBr1FD3oAga46CmRfvSs5mT+k7uYQTCDfMpEs=\",\"Jq0ieJa3PiNW8FlYDQxKG6htWQey9IdD1DK84cJSzJ8=\",\"F9Ruy0tnL8XatF5yc29SNjMvl9RISPSf7oYcibYqITk=\",\"CV12Io5iYamsvVeYAjyqfQzUp53cn4JbfpBEIr+0X1Q=\",\"IPTZtl4GtExbB+rE2ocCQ3+byI5WKWU2HnuMqsUVyls=\"]],\"MerkleProofsNftBefore\":[\"H5MB1QbSwkmPGEemLafXBd0PUEPOCfz1wn/Qe0OpOWI=\",\"CAMkwudv0hWWPIOwEa741gEzSBYXoMHFVkmD/KclJzI=\",\"DL7NlJYY3ykJQdrqtdViB9XPiZ7oweggjI33VIZf+OA=\",\"DHa545fm3ihXkSwsW7Nn3ujLligNakk0rPJXc7gjUns=\",\"EWtpN/Ud9l3+/lQ77MMZqqovEHAN/fSC8nA40SXU+yE=\",\"Jr3nWnrLVYMzvlJnRYu3SspNkWza8Me5dVnWJsVvkq0=\",\"H/Ch6AXi+iaPg9NLzmKrII8nBTOd96PR0hkTJq4ZxkI=\",\"JS3TvRJ1XofKOp902rdo53J1BQP7IdfF8ZKAqzpSHbg=\",\"ATcpMKvYWAcSh5Oz25oagVFKBhElSwwVjW9GVKNaMWw=\",\"BzHINPGmWithYYtRuM361T+PfSz74QQ9v/cQO6NnAEY=\",\"A5NNTV0t0vEWNLXSvSEn7iRv5/5WVRPFrlcTw49gzMw=\",\"JNfg3dTqxVe2ZlL7q1/jT28W5DVmahuuifkOUir8FEI=\",\"GrX/q3yXUqVAnspd08kwPjeh/l8QpM8oi5KgQVNU4FA=\",\"G5Tdp91escCk+hHmX6SuSz5uCk5MqXKCewL5zSZGSD4=\",\"EXGe7i3fF24gbZIEhkF7eDij+xHV5+eLesD505sNzTk=\",\"DKZpdkJqXDpEh2rOC3RjP1HuVCsfpqmEY6F6ADgbMUQ=\",\"AI8fgeRKgylGexsmN9ZsbKYYUjcGEkoUevohkcWl00M=\",\"L0K7Wg0laxNmgaQLv3qGLGUMTXn0ocDya2HrnGRUeEM=\",\"JlAwvSAUVoWr7uMX6mlEtYJalG3owhX7g9NyqC0UlTY=\",\"Ad3r6EWwzu1L+3P6fto/ebY+/YLbR+kgo/KJ/avIyUs=\",\"CTqGJagyLoNKUy2Kbn95x9Jn/rkvD6t22FejIfOmFlg=\",\"Fa1N9osHJ7lCqbb6DJ1GVDLbJ5pQoPf1SrmQOl5ge3k=\",\"CistkoBZE3ptmSuWadaSACFPUJDaT/eOr9c+MDksRX4=\",\"FOYdXpLSnb3o/wKWdE047M9wbqtUrSXQ8gZLJJVyIrE=\",\"FG/bpdpbaTIfOiBcgzVkAGkgY/JqCrV2dEKGbGbOx1g=\",\"Hk81d4uO0ctgb+F8dgj2nFtVxiayIHiP3KAXY/9SQs0=\",\"A8CGpwwG2OyJ+kf6z56Y2Y5U/AAlFRFLK+x2NeoQn+A=\",\"HrHUmeSxf5YNZboqqzkZj2ZYBvHAvE10BKAse7LsMPk=\",\"EbTwaNs0LvI3PkmM9gsLpo0om37r/esJgBs8jz2wVKo=\",\"DRilkQhww8oxdcc6jcj9PuCKpAdy4+QEl6sK4kANCZo=\",\"AZOTv7OqKTpeLEh6gJ9SeLwizgJ0+JWFtSZ1AFsrGs8=\",\"KkJslgbcxYJ1N0mF5vtcwq9uJA0KR7HYDNzg35BOu5o=\",\"HbYl9g6Njdw1ge8jDO+B8mvEeJlOS/RZ9k+q7hnMwOc=\",\"GvW80b49qFo7Btk3eF0zJ2SJMZHiAQFkRebCDVJ4o9I=\",\"ElqToYkzOWbi5o1y07Pu/YQmT3JA2rgzuxmhagW9tGc=\",\"J+noCvAs4JciyWT5dm0sWag398t8ywHnHzCi/p18at4=\",\"FVaaewz8InethS3u0CfAUGMpii/6QjfhsvlrOP1mATA=\",\"FP7+rG41SHrQ0SOkSuHIuJ+SNsDvwGR542haYtrix1k=\",\"GnGbtWqHJ0f8jAWMufK4pQPPa6HR7oOKn41z4dfOOcg=\",\"HUMlXGHRQOByg1Ugbli/i8anfGcWAVzIP3KX+4n6S0A=\"],\"StateRootAfter\":\"IcXB8kWYivltKTzI1FWgtA+DFfN9rTcsF2il/4woXK4=\"}],\"Gas\":{\"GasAssetCount\":2,\"AccountInfoBefore\":{\"AccountIndex\":1,\"AccountNameHash\":\"\",\"AccountPk\":{\"A\":{\"X\":0,\"Y\":0}},\"Nonce\":0,\"CollectionNonce\":0,\"AssetRoot\":\"GtZCjLWJ+BiXQINqtGjcwIx8EEpKtA9NRovgZQek+jk=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0},{\"AssetId\":1,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]},\"MerkleProofsAccountBefore\":[\"InXCyN5MViKX0USCBjJUSB55ub/X+TOKwafu7mMP2mI=\",\"BbM7CeFco1bnoP+EXzWqEq97pm0AIUlKGb0AOsi24Xs=\",\"CO/3B1OR8+ExBAmZLdvq+y7JOZytdU/T5WIH9L5W/8M=\",\"AfYygkZh7jvClhV/00a8QRd0jHBazPHgL7IkiCnNON0=\",\"HZIpJ3oov/YqtpeqBZYz2cVvL9MHc+Hxic4oAs2azko=\",\"EPalwaWTBPDKMbgC2Olu9DAVCy4FohCuQtnZSx83c80=\",\"GBoLqjeyqmjEd1jNl07ShpZ9mjvGNq1Cr8e/n37tfN0=\",\"EsbuF6ELNG6W2NUk4unXV+J7mVucI5tf6EBL0bY3f9s=\",\"J8ZpV92DsmO8SoHKgd38Tzm8GSu+FciKWwMBoLacUNc=\",\"JARv5hBXEJ0D33/Vp60Uqsbbop+L5W/orbPoVYj0U7g=\",\"FyCyMeQig6KNayj5e1BGnb+idTTHpBms+t62PbWtW2w=\",\"DiTYYj8tDURSNaiXdgj2HZjM9kxsuFzzMl1iaJDBkqQ=\",\"AAQlYtym1SCx+ZXUfQneKaQ0s4EiHM3xA0RDClhONhE=\",\"GNzh6J8ma0g5PYwDN82LPg0QL5c23bSlKRMs3UMx67c=\",\"CasXSG+Fl7d7LqrhibDU70BcBqgxx4y7KV0GTG4F86A=\",\"KUNhAnPJ1RDl562V3f983aEIjyg79Z+w7UZAAWVGE8s=\",\"GI6i92i1TyiyDxElx9mCODGz5kq60rb1qBx9nuNoed0=\",\"GZTU6MidGuVnHNshNe7ez3ic9XG21Ui8kVmLMiSRi5U=\",\"AirfELhjjvRRDU0r7Lyg4SBvPoLSki+9T03NeKZjMTo=\",\"AWH4FKi97BhCmO0MgoJE5A/Tb7ViFVtC/R1f5Oli5F4=\",\"AvKirFoKFQOx2urE22lFDF5dGMm8olKDuH1hvwqJg64=\",\"JWQHHBP9qT2fshisyfsUqrdpaintuFLbyopn4Lm7xfs=\",\"AK0SN8q8Lni2yOx5EakInoCNhEAlshXBDdRf+zyTbp8=\",\"KNO7USWpXQjqN0UCTv6pTghdkUG1AohQFb5xAZa5xYA=\",\"FNVNP8BekY5FHbEwAr/ChSx+1muq82J/E5noaNqpBhM=\",\"K+Yv3RkQFwAse9fxjwAgULAn8DQKeC6tILbFrhlDVB0=\",\"GqyqSHuHXtExnBxLEegrPnMJB6C7XDFW3Y3oxdN6L+o=\",\"IjLZ/0ZBr1FD3oAga46CmRfvSs5mT+k7uYQTCDfMpEs=\",\"Jq0ieJa3PiNW8FlYDQxKG6htWQey9IdD1DK84cJSzJ8=\",\"F9Ruy0tnL8XatF5yc29SNjMvl9RISPSf7oYcibYqITk=\",\"CV12Io5iYamsvVeYAjyqfQzUp53cn4JbfpBEIr+0X1Q=\",\"GvI1Vd5oAQ/bqng06pfQ6a/CXrrmTrE+nb6lXKP29OM=\"],\"MerkleProofsAccountAssetsBefore\":[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"FTJM/63uEvv6D+qsIAMsa4bpohmn86uvfN59A/+H0f8=\",\"ILZsuVI4UGvnGQPwjXvgepL1pLoTvF1q7wYki78PGRM=\",\"Cafa2e8frf3AIeeBmaJANpSvfHf80oYDHkpMVVi2U5Q=\",\"Gl+riWk8KrVAwbcRKCYl9kZCNU0D0jCM1Q8/X3h74R4=\",\"I1rLGfDVy5zxVErn7amY1IjmnSnWn1O3/GLrifdxB3M=\",\"GqHECZ6+A/k6vByQTyCFSNAlBMGZ7ycRoY7jQQlkbhk=\",\"IbvTWBAn8d4PKNj2MmlXdwCG487mUp4JocrgoxfO+48=\",\"AB887XbshntIfM5vcB108u2vK6jvop8h73U7XfWts4Y=\",\"AX40KYXth01MNR71cBWfA2L+E86a+guDGnNQSV54sw4=\",\"HlfEvtfn6KBvS9IJAb58Q5yKC8vb0Hho6ILjVI0m7Yo=\",\"H4cEBTQO+svzZ87ZgA1fYRSMhKg5RKDsDK987tMG9yE=\",\"J+mylRlVQq8zoLQiCM2piW7TQzL8TQqZElp1I+FUPEA=\",\"CX9itoG8P1dbOOupeDHEUp6b6cMtN2t6ysW6qbs0Avk=\",\"DBT6cwL/8x/zrFBdXPZDny/627LG6s60Hzeo9kq71rs=\",\"Bz+NfP5WBA3hHqrEJcFy4OBOJwJfJ8KQq6FGk6WfaHs=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"FTJM/63uEvv6D+qsIAMsa4bpohmn86uvfN59A/+H0f8=\",\"ILZsuVI4UGvnGQPwjXvgepL1pLoTvF1q7wYki78PGRM=\",\"Cafa2e8frf3AIeeBmaJANpSvfHf80oYDHkpMVVi2U5Q=\",\"Gl+riWk8KrVAwbcRKCYl9kZCNU0D0jCM1Q8/X3h74R4=\",\"I1rLGfDVy5zxVErn7amY1IjmnSnWn1O3/GLrifdxB3M=\",\"GqHECZ6+A/k6vByQTyCFSNAlBMGZ7ycRoY7jQQlkbhk=\",\"IbvTWBAn8d4PKNj2MmlXdwCG487mUp4JocrgoxfO+48=\",\"AB887XbshntIfM5vcB108u2vK6jvop8h73U7XfWts4Y=\",\"AX40KYXth01MNR71cBWfA2L+E86a+guDGnNQSV54sw4=\",\"HlfEvtfn6KBvS9IJAb58Q5yKC8vb0Hho6ILjVI0m7Yo=\",\"H4cEBTQO+svzZ87ZgA1fYRSMhKg5RKDsDK987tMG9yE=\",\"J+mylRlVQq8zoLQiCM2piW7TQzL8TQqZElp1I+FUPEA=\",\"CX9itoG8P1dbOOupeDHEUp6b6cMtN2t6ysW6qbs0Avk=\",\"DBT6cwL/8x/zrFBdXPZDny/627LG6s60Hzeo9kq71rs=\",\"Bz+NfP5WBA3hHqrEJcFy4OBOJwJfJ8KQq6FGk6WfaHs=\"]]}}"
		var cryptoBlock *circuit.Block
		err = json.Unmarshal([]byte(witnessJson), &cryptoBlock)
		if err != nil {
			return
		}
		blockWitness, err := circuit.SetBlockWitness(cryptoBlock)
		if err != nil {
			return
		}
		witness, err := frontend.NewWitness(&blockWitness, ecc.BN254)
		err = oR1cs.IsSolved(witness, backend.WithHints(types.PubDataToBytes))
		if err != nil {
			fmt.Println(err)
		}

		err = groth16.SetupLazyWithDump(oR1cs, sessionName+fmt.Sprint(differentBlockSizes[i]))
		if err != nil {
			panic(err)
		}
		{
			verifyingKey := groth16.NewVerifyingKey(ecc.BN254)
			f, _ := os.Open(sessionName + fmt.Sprint(differentBlockSizes[i]) + ".vk.save")
			_, err = verifyingKey.ReadFrom(f)
			if err != nil {
				panic(fmt.Errorf("read file error"))
			}
			f.Close()
			f, err := os.Create("ZkBNBVerifier" + fmt.Sprint(differentBlockSizes[i]) + ".sol")
			if err != nil {
				panic(err)
			}
			err = verifyingKey.ExportSolidity(f)
			if err != nil {
				panic(err)
			}
		}
	}
}

func optionalBlockSizesInt() []int {
	blockSizesStr := strings.Split(*optionalBlockSizes, ",")
	blockSizesInt := make([]int, len(blockSizesStr))
	for i := range blockSizesStr {
		v, err := strconv.Atoi(blockSizesStr[i])
		if err != nil {
			panic(err)
		}
		blockSizesInt[i] = v
	}
	return blockSizesInt
}

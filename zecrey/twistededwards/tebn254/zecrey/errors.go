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

package zecrey

import "errors"

var (
	ErrInvalidParams            = errors.New("err: invalid params")
	ErrIncorrectBalance         = errors.New("err: incorrect balance")
	ErrInvalidSwapProof         = errors.New("err: invalid swap proof")
	ErrInvalidEncryption        = errors.New("err: invalid encryption")
	ErrStatements               = errors.New("err: invalid statements")
	ErrPostiveBStar             = errors.New("err: bstar should be positive")
	ErrNegativeBStar            = errors.New("err: bstar should be negative")
	ErrInvalidChallenge         = errors.New("err: invalid challenge")
	ErrInvalidBPParams          = errors.New("err: invalid bulletproof prove params")
	ErrInconsistentPublicKey    = errors.New("err: inconsistent public key")
	ErrInsufficientBalance      = errors.New("err: insufficient balance")
	ErrInvalidDelta             = errors.New("err: you cannot transfer to yourself positive amount")
	ErrInvalidBStar             = errors.New("err: bstar should smaller than zero")
	ErrElGamalDec               = errors.New("err: can not dec elgamal enc")
	ErrInvalidWithdrawProofSize = errors.New("err: invalid withdraw proof size")
)

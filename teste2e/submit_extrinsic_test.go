// Go Substrate RPC Client (GSRPC) provides APIs and types around Polkadot and any Substrate-based chain RPC calls
//
// Copyright 2019 Centrifuge GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package teste2e

import (
	"fmt"
	"github.com/centrifuge/go-substrate-rpc-client/rpc/author"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client"
	"github.com/centrifuge/go-substrate-rpc-client/config"
	"github.com/centrifuge/go-substrate-rpc-client/signature"
	"github.com/centrifuge/go-substrate-rpc-client/types"
)

func TestChain_SubmitExtrinsic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode.")
	}

	api, err := gsrpc.NewSubstrateAPI(config.Default().RPCURL)
	if err != nil {
		panic(err)
	}

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	bob, err := types.NewAddressFromHexAccountID("0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48")
	if err != nil {
		panic(err)
	}

	// Uncomment this to send an anchor
	//docRoot, err := types.NewHashFromHexString("0xc74ca1a0e0c6ab715a05d7c89949986b274dac73a9eff010c6a1dc1b74fc6c2e")
	//if err != nil {
	//	panic(err)
	//}
	//signRoot, err := types.NewHashFromHexString("0xc74ca1a0e0c6ab715a05d7c89949986b274dac73a9eff010c6a1dc1b74fc6c22")
	//if err != nil {
	//	panic(err)
	//}

	c, err := types.NewCall(meta, "Balances.transfer", bob, types.UCompact(6969))
	// Uncomment this to send an anchor
	//c, err := types.NewCall(meta, "Anchor.pre_commit", docRoot, signRoot)
	if err != nil {
		panic(err)
	}

	ext := types.NewExtrinsic(c)

	// blockHash, err := api.RPC.Chain.GetBlockHashLatest()
	// if err != nil {
	// 	panic(err)
	// }

	era := types.ExtrinsicEra{IsMortalEra: false}

	genesisHash, err := api.RPC.Chain.GetBlockHash(0)
	if err != nil {
		panic(err)
	}

	rv, err := api.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		panic(err)
	}

	key, err := types.CreateStorageKey(meta, "System", "AccountNonce", signature.TestKeyringPairAlice.PublicKey)
	if err != nil {
		panic(err)
	}

	var nonce uint32
	err = api.RPC.State.GetStorageLatest(key, &nonce)
	if err != nil {
		panic(err)
	}

	o := types.SignatureOptions{
		// BlockHash:   blockHash,
		BlockHash:   genesisHash, // BlockHash needs to == GenesisHash if era is immortal. // TODO: add an error?
		Era:         era,
		GenesisHash: genesisHash,
		Nonce:       types.UCompact(nonce),
		SpecVersion: rv.SpecVersion,
		Tip:         0,
	}

	err = ext.Sign(signature.TestKeyringPairAlice, o)
	if err != nil {
		panic(err)
	}

	extEnc, err := types.EncodeToHexString(ext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n", extEnc)

	auth := author.NewAuthor(api.Client)

	startBlock, err := api.RPC.Chain.GetBlockLatest()
	assert.NoError(t, err)
	startBlockNumber := startBlock.Block.Header.Number
	fmt.Printf("Start Block number: %d\n", startBlockNumber)

	hsh, err := auth.SubmitExtrinsic(ext)
	if err != nil {
		panic(err)
	}
	assert.NoError(t, err)
	fmt.Printf("HASH %x\n", hsh)

	currenBlockNumber := startBlockNumber
	var foundBlock *types.SignedBlock
	var idxBlock int
	for {
		fmt.Println("Processing block", currenBlockNumber)
		nBlock, err := api.RPC.Chain.GetBlockLatest()
		if err != nil {
			fmt.Println("AA0", err)
			break
		}
		//nhBlock, err := api.RPC.Chain.GetBlockHash(uint64(currenBlockNumber))
		//if err != nil {
		//	fmt.Println("AA", err)
		//	break
		//}
		//assert.NoError(t, err)
		//nBlock, err := api.RPC.Chain.GetBlock(nhBlock)
		//if err != nil {
		//	fmt.Println("BB", err)
		//	break
		//}
		idxBlock = isExtrinsicInBlock(ext, nBlock.Block)
		if idxBlock > -1 {
			foundBlock = nBlock
			break
		}
		currenBlockNumber = nBlock.Block.Header.Number
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("Found extrinsic in block", foundBlock.Block.Header.Number, "with index", idxBlock)

	meta, err = api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	key, err = types.CreateStorageKey(meta, "System", "Events", nil)
	if err != nil {
		panic(err)
	}

	bh, err := api.RPC.Chain.GetBlockHash(uint64(foundBlock.Block.Header.Number))
	if err != nil {
		panic(err)
	}

	fmt.Printf("bh %x\n", bh)
	fmt.Printf("key %s\n", key.Hex())

	var er types.EventRecordsRaw
	err = api.RPC.State.GetStorage(key, &er, bh)
	if err != nil {
		panic(err)
	}
	fmt.Printf("EVR %x\n", er)
	e := types.EventRecords{}
	err = er.DecodeEventRecords(meta, &e)
	if err != nil {
		panic(err)
	}

	fmt.Println("Failed Len: ", len(e.System_ExtrinsicFailed))
	fmt.Println("Failed Err: ", e.System_ExtrinsicFailed[0].DispatchError)
	fmt.Println("Failed Ph AsApplyExt: ", e.System_ExtrinsicFailed[0].Phase.AsApplyExtrinsic)
	fmt.Println("Failed Ph IsApplyExt: ", e.System_ExtrinsicFailed[0].Phase.IsApplyExtrinsic)
	fmt.Println("Failed Ph IsFinal: ", e.System_ExtrinsicFailed[0].Phase.IsFinalization)
	fmt.Println("Failed Topc: ", len(e.System_ExtrinsicFailed[0].Topics))
	fmt.Println("Succeeded Len: ", len(e.System_ExtrinsicSuccess))
	fmt.Println("Succeeded Ph AsApplyExt: ", e.System_ExtrinsicSuccess[0].Phase.AsApplyExtrinsic)
	fmt.Println("Succeeded Ph IsApplyExt: ", e.System_ExtrinsicSuccess[0].Phase.IsApplyExtrinsic)
	fmt.Println("Succeeded Ph IsFinal: ", e.System_ExtrinsicSuccess[0].Phase.IsFinalization)
	fmt.Println("Succeeded Topc: ", len(e.System_ExtrinsicSuccess[0].Topics))

}

func isExtrinsicInBlock(ext types.Extrinsic, block types.Block) int {
	found := -1
	for idx, xx := range block.Extrinsics {
		if xx.Signature == ext.Signature {
			found = idx
			break
		}
	}
	return found
}

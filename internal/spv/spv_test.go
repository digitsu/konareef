// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// spv_test.go — known-answer and refusal tests for the spv parsers.
//
// External known-answer vectors:
//   - the BRC-74 example BUMP and its root (the BRC-74 specification,
//     also in the Go and Rust BSV SDK test suites);
//   - a BRC-62 V1 BEEF and a BRC-96 V2 BEEF from the same suites;
//   - the BRC-42 public derivation vectors (testdata/
//     brc42-public-vectors.json, from the Go BSV SDK);
//   - a trimmed compound BUMP from BSV mainnet block 969172 with an
//     empty level 9 (testdata/compound-bump-969172.json).
//
// Everything else is built with spvtest and never touches a network.
package spv_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/digitsu/konareef/internal/spv"
	"github.com/digitsu/konareef/internal/spv/spvtest"
)

const (
	brc74Hex   = "fe8a6a0c000c04fde80b0011774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30fde90b02004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8fdea0b025e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998fdeb0b0102fdf405000671394f72237d08a4277f4435e5b6edf7adc272f25effef27cdfe805ce71a81fdf50500262bccabec6c4af3ed00cc7a7414edea9c5efa92fb8623dd6160a001450a528201fdfb020101fd7c010093b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e8501bf01015e005881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8012e00e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff30116008120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d010a00502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae430104001ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45010301010000af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4"
	brc74Root  = "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4"
	brc74TxID1 = "304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711"
	brc74TxID2 = "d888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00"
	brc74TxID3 = "98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e"

	beefSetV2Hex = "0200beef03fef1550d001102fd20c2009591fd79f7fb1fbd24c2fdc4911da930e1d7386f0216b6446b85eea29f978f1bfd21c202ac2a05abdae46fc2555c36a76035dedbf9fac4fc349eabffbd9d62ba440ffcb101fd116100cabeb714ea9a3f15a5e4f6138f6dd6b75bab32d8b40d178a0514e6e1e1b372f701fd8930007e04df7216a1d29bb8caabd1f78014b1b4f336eb6aee76bcf1797456ddc86b7501fd451800796afe5b113d8933f5eef2d180e72dc4b644fd76fb1243dfb791d9863702573701fd230c007a6edc003e02c429391cbf426816885731cb8054410599884eed508917a2f57c01fd100600eaa540de74506ed6abcb48e38cc544c53d373269271a7e6cf2143b7cc85d7ea401fd0903001e31aa04628b99d6cfa3e21fb4a7e773487ebc86a504e511eaff3f2176267b9401fd85010031e0d053497f85228b02879f69c4c7b43fb5abc3e0e47ea49a63853b117c9b5001c30083339d5a5b97ad77b74d3538678bb20ea7e61f8b02c24a625933eb496bebd3480160008ee445baec1613d591344a9915d77652f508e6442cd394626a3ff308bcb151f1013100f3f68f2a72e47bb41377e9e429daa496cd220bdcf702a36a209f9feba58d5552011900a01c52f4099bc7bdfea772ab03739bf009d72f24f68b5c4f8cc71a8c4da80804010d00c2ce2d5bfb9cbab9983ae1c871974f23a32c585d9b8440acc4ef5203c1d6c05401070072c7fc59a1717e90633f10d322e0f63272ae97c017d1efae04e4090abeeafac3010200a7aa5fa5576d1de6dd0e32d769592bc247be7bbd0b3e36e2d579fa1ec7d6ebce010000090cba670bea2e0d5c36e979e4cf9f79ad0874d734fb782fec2496d4c554e321010100d963646680643df73c34d7fa16f173595cf32a9ed6f64d2c8ee88a8af6b7bf52fedf590d001202fe66130200023275c6dde10d32d61af52b412b1e3956b5cd085605cd521778f11d53849fdb0cfe6713020000cd5e2298cf4d809c698c8adeeab66718e6b75b3d528bce74e6e01b984c736df901feb209010000736013454e087c89d813c99a043c9029cf2d427815c6a98ba3641c384ae52c4701fdd884007f742824bddca1582e4ded866d9609d9473397f8b86625376be74684f7fb947f01fd6d4200eb7f54ce4f920a3e4c7f96ef6b2d199c519df1b1286415581187ca608f3e47b801fd372100fa6c1c8cba3d3d5d030cd98eb91498cdffe70f0dad1000e123157d5dac22e22a01fd9a1000104c0294e478fbcac4e2325403afd86370c86043f295978b809004b2687a6c9a01fd4c08009ef5a5eaf16cab45a239c43852296ab323ca21faf256ab9768dd0a2f39970ec201fd2704006161cbd1755b66815eb69613b574920e9e836c8c3772aa2260ad3639848d520b01fd1202005e04b5afc0ea8d29dc22b611536832a2a2e7c860bbf4227ce0bdcc8a0e66284601fd0801009719f5f90e3937f3921045d202522fe315da1331acc3cce472c4b084d0debe65018500d79a1c3d45a3c41bf6526a9adbac2676159d2f3c753d7d3b6dba1dc3cbdd3c520143006b88b582d985bffc511556e471a6a20cfda2d41837245329f714214e009a3e48012000c1840dbdfc3014f1e912882b971c030fd21c0b023c01fe6fd7470d6d9bb2ab86011100f9c3de08d38588e225a5ee5334a3c03771a0b51318ca388dd1b5826951604d750109006e2b2e926c86214620d306a59522eee438a79157e9360cb76ee14a868fccc482010500d5c43ea372c432861db73ba0a6897fa29855e542a6ed910626dfb8954d94fa47010300d7863bafb5ca841ca0b13736fced1d492f0f741cb0a2beab1cafa517c878ae2c010000174ccda0879c20b85fa26d423deb0b34c5f2787127e244ccacfae39b5ba8fea7feeb590d001602fe46b3060002fa6ae8371111956f74412e3b1effcbd4fcb278124b6365b34c8cc20a5287bafffe47b306000011883eed76bdc7e7fb79efe23e3c50aa825ade46d79895de1a246e3d69a5b8cf01fea2590300009c92d7f67ac06e4bce0de4f18f438056f25138ee1a0cf61ed3a6d7f32261339b01fed0ac01000006178026214d61dc19c91cb5c08481f2f3daf03392c359de424cbd5d7135c5cf01fd69d6000174f6863438909d648fea32cdd65cbf457ab717f9be327d5d4352dbf157671e01fd356b0059536ea55010906b7071e36f78b20faaaede46a7f27ba4916dc1655836c73de701fd9b3500dee845c02c827dbcd862de359f5e6ad0ecca59213d9eb01896374d9efb7af9fd01fdcc1a00b22861b84b4537dfdaa8eb51957a51007af7836677ad14074601de6cd6c2871c01fd670d00591e76e7b07b26a6d7e940ec4f84497d9f3c7be111b15c336b24d83227db0c1001fdb20600f142d0ff9b2ddb7c21d8913f02adc7abc51fcdd5253154339450b87b59859aa601fd580300ce0307ff2027d405b8afa8a5c8834e9cc8bd073c4f463c3657562bbdb7843fe601fdad010027a3ce3a9829a3df0d9074099a6a3d76c81600a6a9c50f6cf857fb823c1a783901d700cca7689680c528f0a93fd9c980577016b37ce67ce75b1d728c4fa23008b1652b016a00b74bd3ab6c94f1216a803849afc254f37eea378c89167ff0686223db82767e3a013400434d5f48f733bb69fc5f0bd8238ffaec8d002951e6a1b52484fcc05819078372011b0053fef8153f4aed8aa8bdebeae0a6c1aa7712b84887fb565bcd9232fdd60fb0c0010c00009d9f21a9bc9e9d8c99aac9a1df47ffe02334fcb8bc8f3797d64c2564b3bf44010700838a284a4ee33c455b303e1eb23428b35d264b35c4f4b42bd6c68f1a7279f38801020042820e1ab5dbb77b0a6f266167b453f672d007d0c6eddc6229ce57c941f46c670100002c0da37e0453e7d01c810d2280a84792086b1fe1bc232e76ef6783f76c57757601010048746ad4d10a562bb53d2ed29438c9dfd0a6cacb78429277072e789d4d8dd8c101010091a52bf4a100e96dba15cbff933df60fcb26d95d6dd9b55fd5e450d5895e4526010100c202dcbdece72a45a1657ff7dbd979b031b1c8b839bc9a3b958683226644b736030100020000000140f6726035b03b90c1f770f0280444eeb041c45d026a8f4baaf00530bdc473a5020000006b483045022100ccdf467aa46d9570c4778f4e68491cc51dff4b815803d2406b6e8772d800f5ad02200ff8f11a59d207c734e9c68154dcef4023d75c37e661ab866b1d3e3ea77e6bda4121021cf99b6763736f48e6e063f99a43bfa82f15111ba0e0f9776280e6bd75d23af9ffffffff0377082800000000001976a91491b21f8856b862ff291ca0ac2ec924ba2419113788ac75330100000000001976a9144b5b285395052a61328b58c6594dd66aa6003d4988acf229f503000000001976a9148efcb6c55f5c299d48d0c74762dd811345c9093b88ac0000000001010200000001bcfe1adc5e99edb82c6a48f44cbae19bc0e5d31f9c8e4b3a92d6befb1cb2e510020000006a4730440220211655b505edd6fe9196aba77477dac5c9f638fe204243c09f1188a19164ac7f022035fb8640750515ca85df8197dec87a76db5c578f05b8ae645e30d8f70d429a324121028bf1be8161c50f98289df3ecd3185ed2273e9d448840232cf2f077f05e789c29ffffffff03d8000400000000001976a9144f427ee5f3099f0ac571f6b723a628e7b08fb64c88ac75330100000000001976a914f7cad87036406e5d3aef5d4a4d65887c76f9466788ac27db1004000000001976a9143219d1b6bd74f932dcb39a5f3b48cfde2b61cc0088ac0000000001020100000002e646efa607ff14299bc0b0cfaa65e035feb493cc440cb8abb8eb6225f8d4c1c4000000006b483045022100b410c4f82655f56fc8de4a622d3e4a8c662198de5ca8963989d70b85734986f502204fe884d99aa6ffd44bb01396b9f63bebcb7222b76e6e26c2bd60837ff555f1f8412103fda4ece7b0c9150872f8ef5241164b36a230fd9657bc43ca083d9e78bc0bcba6ffffffff3275c6dde10d32d61af52b412b1e3956b5cd085605cd521778f11d53849fdb0c000000006a473044022057f9d55ace1945866be0f83431867c58eda32d73ae3fdabed2d3424ebbe493530220553e286ae67bcaf49b0ea1d3163f41b1b3c91702a054e100c1e71ca4927f6dd8412103fda4ece7b0c9150872f8ef5241164b36a230fd9657bc43ca083d9e78bc0bcba6ffffffff04400d0300000000001976a9140e8338fa60e5391d54e99c734640e72461922d9988aca0860100000000001976a9140602787cc457f68c43581224fda6b9555aaab58e88ac10270000000000001976a91402cfbfc3931c7c1cf712574e80e75b1c2df14b2088acd5120000000000001976a914bd3dbab46060873e17ca754b0db0da4552c9a09388ac00000000"

	brc62Hex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"
)

// display decodes a display-order hex hash into internal order.
func display(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad hash %q", s)
	}
	var h [32]byte
	copy(h[:], b)
	return spv.Reverse32(h)
}

// mustHex decodes hex or fails.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBUMP_BRC74KnownAnswer(t *testing.T) {
	b, err := spv.ParseBUMP(mustHex(t, brc74Hex))
	if err != nil {
		t.Fatal(err)
	}
	if b.BlockHeight != 813706 {
		t.Fatalf("height = %d", b.BlockHeight)
	}
	want := display(t, brc74Root)
	for _, id := range []string{brc74TxID1, brc74TxID2, brc74TxID3} {
		got, err := b.ComputeRoot(display(t, id))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if got != want {
			t.Fatalf("%s: root %x, want %x", id, spv.Reverse32(got), spv.Reverse32(want))
		}
	}
	if _, err := b.ComputeRoot(sha256.Sum256([]byte("absent"))); !errors.Is(err, spv.ErrMalformed) {
		t.Fatalf("absent txid: %v", err)
	}
}

func TestBUMP_BuiltTreesMatchEveryIndex(t *testing.T) {
	for n := 2; n <= 9; n++ {
		var ids [][32]byte
		for i := 0; i < n; i++ {
			ids = append(ids, sha256.Sum256([]byte(fmt.Sprintf("tx-%d-%d", n, i))))
		}
		for i := 0; i < n; i++ {
			raw, root := spvtest.BuildBUMP(100, ids, i)
			b, err := spv.ParseBUMP(raw)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			got, err := b.ComputeRoot(ids[i])
			if err != nil || got != root {
				t.Fatalf("n=%d i=%d: root mismatch (%v)", n, i, err)
			}
			// The path must not prove a different transaction.
			if _, err := b.ComputeRoot(ids[(i+1)%n]); err == nil && n > 2 {
				other, _ := b.ComputeRoot(ids[(i+1)%n])
				if other == root && ids[(i+1)%n] != ids[i^1] {
					t.Fatalf("n=%d i=%d: path proves an unrelated txid", n, i)
				}
			}
		}
	}
}

func TestBUMP_Refusals(t *testing.T) {
	ids := [][32]byte{sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))}
	good, _ := spvtest.BuildBUMP(7, ids, 0)
	cases := map[string][]byte{
		"empty":             {},
		"truncated":         good[:len(good)-1],
		"trailing":          append(append([]byte{}, good...), 0x00),
		"zero tree height":  {0x07, 0x00},
		"tree height > 64":  {0x07, 65},
		"unknown flag":      append([]byte{0x07, 0x01, 0x01, 0x00, 0x09}, make([]byte, 32)...),
		"non-minimal count": {0x07, 0x01, 0xfd, 0x01, 0x00},
		"repeated offset":   append(append([]byte{0x07, 0x01, 0x02, 0x00, 0x00}, make([]byte, 32)...), append([]byte{0x00, 0x00}, make([]byte, 32)...)...),
	}
	for name, raw := range cases {
		if _, err := spv.ParseBUMP(raw); !errors.Is(err, spv.ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

// compoundVector is the mainnet block 969172 vector: a trimmed compound
// BUMP, returned by a BRC-100 wallet, whose level 9 has no leaves.
type compoundVector struct {
	BlockHeight           uint64 `json:"block_height"`
	BlockHash             string `json:"block_hash"`
	TxID                  string `json:"txid"`
	RawTxHex              string `json:"raw_tx_hex"`
	BumpHex               string `json:"bump_hex"`
	HeaderHex             string `json:"header_hex"`
	MerkleRootInternalHex string `json:"merkle_root_internal_hex"`
	EmptyLevels           []int  `json:"empty_levels"`
}

// loadCompoundVector reads testdata/compound-bump-969172.json.
// Input: t. Output: the decoded vector; the test fails on a read error.
func loadCompoundVector(t *testing.T) compoundVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "compound-bump-969172.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v compoundVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestBUMP_CompoundEmptyLevelMainnet(t *testing.T) {
	v := loadCompoundVector(t)
	b, err := spv.ParseBUMP(mustHex(t, v.BumpHex))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if b.BlockHeight != v.BlockHeight {
		t.Fatalf("height = %d, want %d", b.BlockHeight, v.BlockHeight)
	}
	if len(v.EmptyLevels) == 0 {
		t.Fatal("vector lists no empty levels")
	}
	for _, level := range v.EmptyLevels {
		if len(b.Levels[level]) != 0 {
			t.Fatalf("level %d has %d leaves, want 0", level, len(b.Levels[level]))
		}
	}
	got, err := b.ComputeRoot(display(t, v.TxID))
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if hex.EncodeToString(got[:]) != v.MerkleRootInternalHex {
		t.Fatalf("root %x, want %s", got, v.MerkleRootInternalHex)
	}
	header, err := spv.ParseHeader(mustHex(t, v.HeaderHex))
	if err != nil {
		t.Fatal(err)
	}
	if got != header.MerkleRoot {
		t.Fatalf("root %x, header merkle root %x", got, header.MerkleRoot)
	}
	if hash := header.Hash(); hash != display(t, v.BlockHash) {
		t.Fatalf("header hash %x, want %s", spv.Reverse32(hash), v.BlockHash)
	}
	if err := header.CheckWork(spv.DefaultMaxTarget); err != nil {
		t.Fatalf("work: %v", err)
	}
	// Every level-0 txid of the compound path gives the same root.
	for _, l := range b.Levels[0] {
		if l.Flags != spv.LeafTxID {
			continue
		}
		if r, err := b.ComputeRoot(l.Hash); err != nil || r != got {
			t.Fatalf("txid at offset %d: root %x (%v)", l.Offset, r, err)
		}
	}
}

func TestBEEF_CompoundEmptyLevelMainnet(t *testing.T) {
	v := loadCompoundVector(t)
	rawTx, bump := mustHex(t, v.RawTxHex), mustHex(t, v.BumpHex)
	header, err := spv.ParseHeader(mustHex(t, v.HeaderHex))
	if err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string][]byte{
		"v1": spvtest.AtomicBEEFV1(rawTx, bump),
		"v2": spvtest.AtomicBEEFV2(rawTx, bump),
	} {
		a, err := spv.ParseAtomicBEEF(env)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		subject := a.SubjectTx()
		if subject.TxID != display(t, v.TxID) {
			t.Fatalf("%s: subject %x", name, spv.Reverse32(subject.TxID))
		}
		root, err := a.SubjectBUMP().ComputeRoot(subject.TxID)
		if err != nil || root != header.MerkleRoot {
			t.Fatalf("%s: root %x (%v), want header root", name, root, err)
		}
	}
}

func TestBUMP_EmptyLevelRefusals(t *testing.T) {
	leaf := func(off byte, flags byte, seed string) []byte {
		h := sha256.Sum256([]byte(seed))
		return append([]byte{off, flags}, h[:]...)
	}
	// Tree height 2, level 0 empty, level 1 one leaf.
	emptyLevel0 := append([]byte{0x07, 0x02, 0x00, 0x01}, leaf(0, spv.LeafData, "x")...)
	if _, err := spv.ParseBUMP(emptyLevel0); !errors.Is(err, spv.ErrMalformed) {
		t.Fatalf("empty level 0: err = %v, want ErrMalformed", err)
	}

	// Tree height 3: level 0 holds the subject at offset 0 and its
	// sibling at offset 1; level 1 is empty, so the sibling at level 1
	// offset 1 must come from level-0 offsets 2 and 3, which are absent.
	subject := sha256.Sum256([]byte("subject"))
	uncomputable := []byte{0x07, 0x03, 0x02}
	uncomputable = append(uncomputable, append([]byte{0x00, spv.LeafTxID}, subject[:]...)...)
	uncomputable = append(uncomputable, leaf(1, spv.LeafData, "sibling")...)
	uncomputable = append(uncomputable, 0x00)                                                     // level 1: empty
	uncomputable = append(uncomputable, append([]byte{0x01}, leaf(1, spv.LeafData, "top")...)...) // level 2
	b, err := spv.ParseBUMP(uncomputable)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := b.ComputeRoot(subject); !errors.Is(err, spv.ErrMalformed) {
		t.Fatalf("uncomputable node: err = %v, want ErrMalformed", err)
	}

	// The same shape with level-0 offsets 2 and 3 present computes the
	// empty level's node and gives the root of the four-leaf tree.
	ids := [][32]byte{subject, sha256.Sum256([]byte("sibling")), sha256.Sum256([]byte("c")), sha256.Sum256([]byte("d"))}
	computable := []byte{0x07, 0x02, 0x04}
	computable = append(computable, append([]byte{0x00, spv.LeafTxID}, ids[0][:]...)...)
	for i := 1; i < 4; i++ {
		computable = append(computable, append([]byte{byte(i), spv.LeafData}, ids[i][:]...)...)
	}
	computable = append(computable, 0x00) // level 1: empty
	b, err = spv.ParseBUMP(computable)
	if err != nil {
		t.Fatalf("parse computable: %v", err)
	}
	got, err := b.ComputeRoot(subject)
	if err != nil {
		t.Fatalf("computable root: %v", err)
	}
	if want := spvtest.Tree(ids); got != want[len(want)-1][0] {
		t.Fatalf("computable root %x, want %x", got, want[len(want)-1][0])
	}

	// hashLeaf and dupLeaf serialize one level-0 leaf at offset off.
	hashLeaf := func(off, flags byte, h [32]byte) []byte { return append([]byte{off, flags}, h[:]...) }
	dupLeaf := func(off byte) []byte { return []byte{off, spv.LeafDuplicate} }
	h1, h2, h3 := ids[1], ids[2], ids[3]

	// A left child flagged duplicate cannot give its parent: level 0 =
	// {0 subject, 1 data, 2 duplicate, 3 data}, level 1 empty, level 2 =
	// {1 data}.
	leftDup := []byte{0x07, 0x03, 0x04}
	leftDup = append(leftDup, hashLeaf(0, spv.LeafTxID, subject)...)
	leftDup = append(leftDup, hashLeaf(1, spv.LeafData, h1)...)
	leftDup = append(leftDup, dupLeaf(2)...)
	leftDup = append(leftDup, hashLeaf(3, spv.LeafData, h3)...)
	leftDup = append(leftDup, 0x00)                                                      // level 1: empty
	leftDup = append(leftDup, append([]byte{0x01}, hashLeaf(1, spv.LeafData, h3)...)...) // level 2
	if b, err = spv.ParseBUMP(leftDup); err != nil {
		t.Fatalf("parse left duplicate: %v", err)
	}
	if _, err := b.ComputeRoot(subject); !errors.Is(err, spv.ErrMalformed) {
		t.Fatalf("left child flagged duplicate: err = %v, want ErrMalformed", err)
	}

	// A right child flagged duplicate equals its left sibling: level 0 =
	// {0 subject, 1 data, 2 data, 3 duplicate}, level 1 empty. The root,
	// computed here by hand, is
	// sha256d(sha256d(subject||h1) || sha256d(h2||h2)).
	rightDup := []byte{0x07, 0x02, 0x04}
	rightDup = append(rightDup, hashLeaf(0, spv.LeafTxID, subject)...)
	rightDup = append(rightDup, hashLeaf(1, spv.LeafData, h1)...)
	rightDup = append(rightDup, hashLeaf(2, spv.LeafData, h2)...)
	rightDup = append(rightDup, dupLeaf(3)...)
	rightDup = append(rightDup, 0x00) // level 1: empty
	if b, err = spv.ParseBUMP(rightDup); err != nil {
		t.Fatalf("parse right duplicate: %v", err)
	}
	pair := func(l, r [32]byte) [32]byte { return spv.DoubleSHA256(append(append([]byte{}, l[:]...), r[:]...)) }
	wantRoot := pair(pair(subject, h1), pair(h2, h2))
	if got, err := b.ComputeRoot(subject); err != nil || got != wantRoot {
		t.Fatalf("right child flagged duplicate: root %x (%v), want %x", got, err, wantRoot)
	}

	// An absent right child cannot give its parent: level 0 = {0
	// subject, 1 data, 2 data}, offset 3 absent, level 1 empty.
	rightAbsent := []byte{0x07, 0x02, 0x03}
	rightAbsent = append(rightAbsent, hashLeaf(0, spv.LeafTxID, subject)...)
	rightAbsent = append(rightAbsent, hashLeaf(1, spv.LeafData, h1)...)
	rightAbsent = append(rightAbsent, hashLeaf(2, spv.LeafData, h2)...)
	rightAbsent = append(rightAbsent, 0x00) // level 1: empty
	if b, err = spv.ParseBUMP(rightAbsent); err != nil {
		t.Fatalf("parse right absent: %v", err)
	}
	if _, err := b.ComputeRoot(subject); !errors.Is(err, spv.ErrMalformed) {
		t.Fatalf("right child absent: err = %v, want ErrMalformed", err)
	}
}

// atomic wraps a plain BEEF body in an Atomic BEEF envelope.
func atomic(subject [32]byte, body []byte) []byte {
	out := []byte{0x01, 0x01, 0x01, 0x01}
	out = append(out, subject[:]...)
	return append(out, body...)
}

func TestBEEF_BRC62KnownAnswer(t *testing.T) {
	body := mustHex(t, brc62Hex)
	if _, err := spv.ParseAtomicBEEF(atomic([32]byte{}, body)); err == nil {
		t.Fatal("an envelope whose subject is not in the BEEF parsed")
	}
	a, err := parseIgnoringSubject(body)
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != spv.BEEFV1 || len(a.Bumps) != 1 || len(a.Txs) != 2 {
		t.Fatalf("shape: version=%x bumps=%d txs=%d", a.Version, len(a.Bumps), len(a.Txs))
	}
	if a.Bumps[0].BlockHeight != 814435 {
		t.Fatalf("bump height %d", a.Bumps[0].BlockHeight)
	}
	first := a.Txs[0]
	if first.BumpIndex != 0 || a.Txs[1].BumpIndex != -1 {
		t.Fatalf("bump indexes %d %d", first.BumpIndex, a.Txs[1].BumpIndex)
	}
	if _, err := a.Bumps[0].ComputeRoot(first.TxID); err != nil {
		t.Fatalf("root: %v", err)
	}
	// Either transaction can be the subject of an envelope.
	for i, tx := range a.Txs {
		if _, err := spv.ParseAtomicBEEF(atomic(tx.TxID, body)); err != nil {
			t.Fatalf("subject %d: %v", i, err)
		}
	}
}

func TestBEEF_V2KnownAnswer(t *testing.T) {
	body := mustHex(t, beefSetV2Hex)
	a, err := parseIgnoringSubject(body)
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != spv.BEEFV2 || len(a.Bumps) != 3 || len(a.Txs) != 3 {
		t.Fatalf("shape: version=%x bumps=%d txs=%d", a.Version, len(a.Bumps), len(a.Txs))
	}
	for i, tx := range a.Txs {
		if tx.Tx == nil || tx.BumpIndex < 0 {
			continue
		}
		if _, err := a.Bumps[tx.BumpIndex].ComputeRoot(tx.TxID); err != nil {
			t.Fatalf("tx %d root: %v", i, err)
		}
	}
}

// parseIgnoringSubject tries every 32-byte window of the raw
// transactions as the subject; the real ids are those for which the
// envelope parses. It is only used on small vectors.
func parseIgnoringSubject(body []byte) (*spv.AtomicBEEF, error) {
	for i := 0; i+32 <= len(body); i++ {
		// Hash every candidate raw-transaction span would be expensive;
		// instead compute the double SHA-256 of every suffix start that
		// begins a version-1 transaction (01 00 00 00).
		if i+4 > len(body) || (body[i] != 0x01 && body[i] != 0x02) || body[i+1] != 0 || body[i+2] != 0 || body[i+3] != 0 {
			continue
		}
		for j := i + 60; j <= len(body); j++ {
			tx, err := spv.ParseTx(body[i:j])
			if err != nil {
				continue
			}
			a, err := spv.ParseAtomicBEEF(atomic(tx.TxID(), body))
			if err == nil {
				return a, nil
			}
		}
	}
	return nil, errors.New("no subject found")
}

func TestBEEF_BuiltV1AndV2(t *testing.T) {
	head := sha256.Sum256([]byte("head"))
	raw := spvtest.BuildTx(1, []spvtest.Output{{Satoshis: 0, Script: spv.OpReturnScript(head[:])}, {Satoshis: 5, Script: []byte{0x51}}})
	ch := spvtest.BuildChain(raw, 900_000, 1_790_000_000, 0)
	for name, env := range map[string][]byte{
		"v1": spvtest.AtomicBEEFV1(raw, ch.BUMP),
		"v2": spvtest.AtomicBEEFV2(raw, ch.BUMP),
	} {
		a, err := spv.ParseAtomicBEEF(env)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		st := a.SubjectTx()
		if st.TxID != ch.TxID || spv.FindOutput(st.Tx, spv.OpReturnScript(head[:])) != 0 {
			t.Fatalf("%s: subject or output wrong", name)
		}
		root, err := a.SubjectBUMP().ComputeRoot(ch.TxID)
		if err != nil || root != ch.Root {
			t.Fatalf("%s: root %v", name, err)
		}
	}
}

func TestBEEF_Refusals(t *testing.T) {
	head := sha256.Sum256([]byte("head"))
	raw := spvtest.BuildTx(1, []spvtest.Output{{Satoshis: 0, Script: spv.OpReturnScript(head[:])}})
	ch := spvtest.BuildChain(raw, 10, 1_790_000_000, 0)
	good := spvtest.AtomicBEEFV1(raw, ch.BUMP)

	wrongSubject := append([]byte{}, good...)
	wrongSubject[4] ^= 0xff
	badVersion := append([]byte{}, good...)
	badVersion[36] = 0x09
	badPrefix := append([]byte{}, good...)
	badPrefix[0] = 0x02
	// The final byte is the bump index (0); point it past the only BUMP.
	badIndex := append([]byte{}, good...)
	badIndex[len(badIndex)-1] = 0x01

	cases := map[string][]byte{
		"empty":          {},
		"prefix":         badPrefix,
		"wrong subject":  wrongSubject,
		"version":        badVersion,
		"bump index oob": badIndex,
		"trailing":       append(append([]byte{}, good...), 0x00),
		"truncated":      good[:len(good)-3],
	}
	for name, env := range cases {
		if _, err := spv.ParseAtomicBEEF(env); !errors.Is(err, spv.ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestTx_Refusals(t *testing.T) {
	raw := spvtest.BuildTx(3, []spvtest.Output{{Satoshis: 1, Script: []byte{0x51}}})
	if _, err := spv.ParseTx(raw); err != nil {
		t.Fatal(err)
	}
	noInputs := []byte{1, 0, 0, 0, 0x00, 0x00, 0, 0, 0, 0}
	ef := append([]byte{1, 0, 0, 0}, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef)
	for name, b := range map[string][]byte{
		"trailing":   append(append([]byte{}, raw...), 0),
		"truncated":  raw[:len(raw)-1],
		"no inputs":  noInputs,
		"extended":   ef,
		"huge count": {1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	} {
		if _, err := spv.ParseTx(b); !errors.Is(err, spv.ErrMalformed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestHeader_CheckWork(t *testing.T) {
	root := sha256.Sum256([]byte("root"))
	h := spvtest.MineHeader([32]byte{}, root, 1_790_000_000)
	parsed, err := spv.ParseHeader(h[:])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.MerkleRoot != root || parsed.Time != 1_790_000_000 {
		t.Fatal("fields")
	}
	if err := parsed.CheckWork(spvtest.TestMaxTarget); err != nil {
		t.Fatalf("mined header: %v", err)
	}
	// The default mainnet floor refuses a test-difficulty header.
	if err := parsed.CheckWork(nil); !errors.Is(err, spv.ErrInsufficientWork) {
		t.Fatalf("default floor accepted a test header: %v", err)
	}
	// A header whose hash misses its own target is refused.
	for nonce := uint32(0); ; nonce++ {
		h[76], h[77], h[78], h[79] = byte(nonce), byte(nonce>>8), byte(nonce>>16), byte(nonce>>24)
		p, _ := spv.ParseHeader(h[:])
		if p.CheckWork(spvtest.TestMaxTarget) != nil {
			break
		}
	}
	if spv.CompactToTarget(0x1d00ffff).Cmp(spv.DefaultMaxTarget) <= 0 {
		t.Fatal("difficulty-1 bits must be below the default floor")
	}
	if spv.CompactToTarget(0x01800000) != nil {
		t.Fatal("negative compact target accepted")
	}
	if _, err := spv.ParseHeader(h[:79]); !errors.Is(err, spv.ErrMalformed) {
		t.Fatal("short header accepted")
	}
}

func TestPinnedFile_RoundTripAndSplice(t *testing.T) {
	head := sha256.Sum256([]byte("h"))
	raw := spvtest.BuildTx(1, []spvtest.Output{{Script: spv.OpReturnScript(head[:])}})
	ch := spvtest.BuildChain(raw, 500, 1_790_000_000, 3)
	var hs [][spv.HeaderSize]byte
	for h := uint64(500); h <= 503; h++ {
		hs = append(hs, ch.Headers.Headers[h])
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "headers.bin")
	if err := os.WriteFile(path, spv.EncodePinnedFile(500, hs), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := spv.LoadPinnedFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if tip, _ := m.TipHeight(context.Background()); tip != 503 {
		t.Fatalf("tip %d", tip)
	}
	if got, _ := m.HeaderAt(context.Background(), 500); got != ch.Header {
		t.Fatal("header 500")
	}
	if _, err := m.HeaderAt(context.Background(), 504); !errors.Is(err, spv.ErrHeaderUnavailable) {
		t.Fatal("out of range")
	}
	// Swapping two headers breaks the parent links.
	hs[1], hs[2] = hs[2], hs[1]
	if _, err := spv.ParsePinnedFile(spv.EncodePinnedFile(500, hs)); !errors.Is(err, spv.ErrHeaderDisagreement) {
		t.Fatalf("spliced file: %v", err)
	}
	if _, err := spv.ParsePinnedFile([]byte("nope")); !errors.Is(err, spv.ErrMalformed) {
		t.Fatal("bad magic")
	}
}

// wocServer serves one block and a tip in the WhatsOnChain JSON shape.
func wocServer(t *testing.T, height uint64, header [spv.HeaderSize]byte, tamperHash bool) *httptest.Server {
	t.Helper()
	p, _ := spv.ParseHeader(header[:])
	h := spv.Reverse32(p.Hash())
	if tamperHash {
		h[0] ^= 1
	}
	root := spv.Reverse32(p.MerkleRoot)
	prev := spv.Reverse32(p.PrevBlock)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case fmt.Sprintf("/block/height/%d", height):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hash": hex.EncodeToString(h[:]), "version": p.Version,
				"merkleroot": hex.EncodeToString(root[:]), "time": p.Time,
				"bits": fmt.Sprintf("%08x", p.Bits), "nonce": p.Nonce,
				"previousblockhash": hex.EncodeToString(prev[:]),
			})
		case "/chain/info":
			_ = json.NewEncoder(w).Encode(map[string]any{"blocks": height + 2})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestRemote_AgreeingAndFirst(t *testing.T) {
	ctx := context.Background()
	head := sha256.Sum256([]byte("h"))
	raw := spvtest.BuildTx(1, []spvtest.Output{{Script: spv.OpReturnScript(head[:])}})
	ch := spvtest.BuildChain(raw, 42, 1_790_000_000, 0)

	good := wocServer(t, 42, ch.Header, false)
	defer good.Close()
	lying := wocServer(t, 42, ch.Header, true)
	defer lying.Close()

	r := &spv.Remote{BaseURL: good.URL}
	got, err := r.HeaderAt(ctx, 42)
	if err != nil || got != ch.Header {
		t.Fatalf("remote header: %v", err)
	}
	if tip, err := r.TipHeight(ctx); err != nil || tip != 44 {
		t.Fatalf("tip %d %v", tip, err)
	}
	if _, err := r.HeaderAt(ctx, 43); !errors.Is(err, spv.ErrHeaderUnavailable) {
		t.Fatalf("missing height: %v", err)
	}
	if _, err := (&spv.Remote{BaseURL: lying.URL}).HeaderAt(ctx, 42); !errors.Is(err, spv.ErrHeaderDisagreement) {
		t.Fatalf("hash mismatch: %v", err)
	}

	// Two sources that disagree on the bytes.
	other := spvtest.MineHeader([32]byte{1}, ch.Root, 1_790_000_001)
	ag := &spv.Agreeing{Sources: []spv.HeaderSource{r, &spv.Memory{Headers: map[uint64][spv.HeaderSize]byte{42: other}, Tip: 50}}}
	if _, err := ag.HeaderAt(ctx, 42); !errors.Is(err, spv.ErrHeaderDisagreement) {
		t.Fatalf("disagreement: %v", err)
	}
	ok := &spv.Agreeing{Sources: []spv.HeaderSource{r, ch.Headers}}
	if h, err := ok.HeaderAt(ctx, 42); err != nil || h != ch.Header {
		t.Fatalf("agreeing: %v", err)
	}
	if tip, _ := ok.TipHeight(ctx); tip != 42 {
		t.Fatalf("agreeing tip %d, want the lower tip", tip)
	}

	unreachable := &spv.Remote{BaseURL: "http://127.0.0.1:1"}
	first := &spv.First{Sources: []spv.HeaderSource{&spv.Memory{}, unreachable, ch.Headers}}
	if h, err := first.HeaderAt(ctx, 42); err != nil || h != ch.Header {
		t.Fatalf("first: %v", err)
	}
	none := &spv.First{Sources: []spv.HeaderSource{&spv.Memory{}, unreachable}}
	if _, err := none.HeaderAt(ctx, 42); !errors.Is(err, spv.ErrHeaderUnavailable) {
		t.Fatalf("first none: %v", err)
	}
}

func TestBRC42_PublicVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "brc42-public-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		SenderPrivateKey   string `json:"senderPrivateKey"`
		RecipientPublicKey string `json:"recipientPublicKey"`
		InvoiceNumber      string `json:"invoiceNumber"`
		PublicKey          string `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for i, v := range vectors {
		var priv [32]byte
		copy(priv[:], mustHex(t, v.SenderPrivateKey))
		got, err := spv.DeriveChildPublicKey(mustHex(t, v.RecipientPublicKey), priv, v.InvoiceNumber)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if hex.EncodeToString(got) != v.PublicKey {
			t.Fatalf("vector %d: got %x want %s", i, got, v.PublicKey)
		}
	}
}

func TestBRC42_AnyoneSignatureVerifies(t *testing.T) {
	id := spvtest.TestIdentityPrivateKey()
	invoice := spv.InvoiceNumber(2, "reef chain anchor", "1")
	msg := []byte("statement")
	der := spvtest.SignAnyone(id, invoice, msg)
	child, err := spv.DeriveAnyonePublicKey(id.PubKey().SerializeCompressed(), invoice)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := secp256k1.ParsePubKey(child)
	sig, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(msg)
	if !sig.Verify(digest[:], pub) {
		t.Fatal("anyone signature does not verify under the derived key")
	}
	// The identity key itself is not the signing key.
	if sig.Verify(digest[:], id.PubKey()) {
		t.Fatal("signature verified under the root identity key")
	}
	if _, err := spv.DeriveAnyonePublicKey([]byte{0x02}, invoice); !errors.Is(err, spv.ErrBadKey) {
		t.Fatal("bad identity accepted")
	}
}

func TestVarInt_RoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 0xfc, 0xfd, 0xffff, 0x10000, 0xffffffff, 0x100000000} {
		enc := spv.AppendVarInt(nil, v)
		// A BUMP with this block height parses back to the same value.
		raw := append(enc, 0x01, 0x01, 0x00, 0x02)
		raw = append(raw, make([]byte, 32)...)
		b, err := spv.ParseBUMP(raw)
		if err != nil || b.BlockHeight != v {
			t.Fatalf("%d: %v", v, err)
		}
	}
}

// TestRemote_TipPathAndCamelCaseFields checks a Bitails-shaped service:
// the tip is at /network/info, and the parent hash field is
// "previousBlockHash". With TipPath set, both the header and the tip
// read; with the default tip path, the tip is unavailable.
func TestRemote_TipPathAndCamelCaseFields(t *testing.T) {
	ctx := context.Background()
	head := sha256.Sum256([]byte("bitails"))
	raw := spvtest.BuildTx(2, []spvtest.Output{{Script: spv.OpReturnScript(head[:])}})
	ch := spvtest.BuildChain(raw, 42, 1_790_000_000, 0)
	parsed, _ := spv.ParseHeader(ch.Header[:])
	hash := spv.Reverse32(parsed.Hash())
	root := spv.Reverse32(parsed.MerkleRoot)
	prev := spv.Reverse32(parsed.PrevBlock)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/block/height/42":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hash": hex.EncodeToString(hash[:]), "version": parsed.Version,
				"merkleroot": hex.EncodeToString(root[:]), "time": parsed.Time,
				"bits": fmt.Sprintf("%08x", parsed.Bits), "nonce": parsed.Nonce,
				"previousBlockHash": hex.EncodeToString(prev[:]),
			})
		case "/network/info":
			_ = json.NewEncoder(w).Encode(map[string]any{"blocks": 45})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	bitails := &spv.Remote{BaseURL: server.URL, TipPath: "network/info"}
	if got, err := bitails.HeaderAt(ctx, 42); err != nil || got != ch.Header {
		t.Fatalf("camelCase header: %v", err)
	}
	if tip, err := bitails.TipHeight(ctx); err != nil || tip != 45 {
		t.Fatalf("tip %d %v", tip, err)
	}
	if _, err := (&spv.Remote{BaseURL: server.URL}).TipHeight(ctx); !errors.Is(err, spv.ErrHeaderUnavailable) {
		t.Fatalf("default tip path on a Bitails-shaped service: %v", err)
	}
}

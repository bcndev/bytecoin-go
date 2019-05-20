// Copyright 2019 The Bytecoin developers
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

package bcnutil

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bcndev/bytecoin-go"
)

func mustHashFromHex(s string) (h bytecoin.Hash) {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	if len(data) != len(h) {
		panic(fmt.Sprintf("wrong hash length: %v vs expected %v", len(data), len(h)))
	}

	copy(h[:], data)

	return h
}

func TestParseExtra(t *testing.T) {
	extra1, err := hex.DecodeString("015e9e370eeac12ec5203f724349cdcd61eb53348dd27ee3519d8cd0a8482bf0f2be09d700205e200000d5f501000000000028bf9255c67f1af0ffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	assert.NoError(t, err)
	fields1 := ParseExtra(extra1)
	assert.Equal(t, "5e9e370eeac12ec5203f724349cdcd61eb53348dd27ee3519d8cd0a8482bf0f2", fields1.PublicKey.String())

	extra2, err := hex.DecodeString("0221006b39b355d3464d6f27ea4fa1192e34ac8e7d0af73c663a5fd56c98dd20fde13801c95d0cc62d1976cd583e1c25b4b8e78f65a14e9e8e2439d92689db5ec1f9d0f0")
	assert.NoError(t, err)
	fields2 := ParseExtra(extra2)
	assert.Equal(t, "c95d0cc62d1976cd583e1c25b4b8e78f65a14e9e8e2439d92689db5ec1f9d0f0", fields2.PublicKey.String())
	assert.Equal(t, "6b39b355d3464d6f27ea4fa1192e34ac8e7d0af73c663a5fd56c98dd20fde138", fields2.PaymentId.String())
}

func TestBlockPoWHashingData(t *testing.T) {
	testData := map[string]string{
		"03078a6f1cb7ed7a9db4751d7b283a0482baff20567173dbfae136c9bceb188e51c40100f2c3a3e4050000000000000000000000000000000000000000000000000000000000000000000000000100000000230321000000000000000000000000000000000000000000000000000000000000000000010b01ff0109f0a42d025d49591eb331323e70ffec0a42ea512c3dc8e2aa7e22cd0101fd190d39f32250d001022f994bd836acd846811a38d565548cf5b46663d1b822a8d6e3819bd00a21a544c096b1020288f224531b0221ec5a07332cc2240e008fb3f827430ce4f946645146ce00553480bbb0210243327c6d3cbcd6d54556bbb6471f85380508ef63418013091ec50d4fd66a109f8088debe01028c12d3dc7b583637fda892118b0ac07ed75b2c3705f9545edbd4196ed6e02cf480a0d9e61d029e3b716471516ab4fb5da1c92e3541cdc8a4f308c8209c22635dfcd7b622cea580b09dc2df0102d395049eeb3f500464e7db53b11b9457397adc0d8d31e36a608b24850a5a354280f092cbdd0802273317f7d2c57015cf7542e54ffa3618d32794131fb3ebe2fdaa064b1dd2c49480c089a9a2f50f0214f41cef90e2358bbe83cfc33549b949e2edd6fceb64cba4c74bab849dd1e16321017a74dbb7d49831cb299b0a3b91f1a69fd6476236fbb041fe3892f9e31cbfd76000":                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           "0100f2c3a3e40500000000000000000000000000000000000000000000000000000000000000000000000011052f38b0c6281b894b87c2187bb9542dc1a64c6d119f88f2c6d4f7975db15701",
		"0407c140d17a359791595e10cacfa1bfc98892603a6b1a8788cd653e7a385ad2e3a00100c2c9d7e5050000000000000000000000000000000000000000000000000000000000000000000000000101000000230321000000000000000000000000000000000000000000000000000000000000000000040001ffefc3040902c8d0074128d6054c2add8a1e11d8641d71064a06b99ce07ec78cb4bd7f9e13596c687d389e230bdc5ba6d4e0e97b51172af8e02a1b71b73d6b0b6b20f8852b1a96b7b9ac02fe0238c16d82cfcb7b0811f75d958e5a21187d4da752bd6be00353986e0baa49dfd2116b494f08656252ce32f844f11902cb52340b103c6a53fc5ad73313d98b14975f02c0843d4eae09bf575616e2ba1d0855e90bb9c3020a699bb53a574fd090ba7bb3b15529b419f9fe695128eeeda1ddd73d9280924d7b8b7707ae215157f12502bd62aafbd60280e892264dc5a63e2c154e8d0819b41ec53b236b49169c21dd3f74d8300610070d1112dbb60e5a5995d69fbb7fe00c3f209bf6b38451862ac3a657b70a0a62ea8721a5155a028090bcfd0253fcd098f870468f64661dbafe448d01ae53512e8d611c179230760363c30202d945d59401c9d4d93899eeb9f1494b742e039cad7b78e3c398b3cd505db81e53880280f882ad16c565687eef99939596b8993a8cd76f0999bd80619cc8bbe9f77fecc8ed8134e06fb06f2958b4a766f784803fe815f9a5aa79278fa9595f575502c4243ee095bea80280c8afa02518649bbfad0ba5746be798a44a402abd6050e79d0ccded07f2f1de462a3523e02e7568441a9dff7a7dc733f75f94933701bae59e48c47126dac3efb54a059c6ee20280e0bcefa757c1d96df5899d3bafc68bc8a60d69f151adc3e74d8da18a0b0aafedf0825cd461e11411f8d795c8a0c7a97f190acb44101d68c9f6f4499a6f36aad48b1fe551a3d70280c0f4c198af0beb484270a9ada91f09eb3cb9be3ba9b4d415c17a204ca9e2b9620ce138cc3920cfa64a1e3faea923221c596c1d8970cf0905531c852eb3ee8e5b12bab026d13df6050403a08d0600": "0100c2c9d7e505000000000000000000000000000000000000000000000000000000000000000000000000545fdf143c9a87e29bf114fc3952314d3592ae0832ddd9c71abe2378c43d9ee501",
	}

	for blockTemplateHex, powHashingDataHex := range testData {
		blockTemplateBlob, err := hex.DecodeString(blockTemplateHex)
		assert.NoError(t, err)

		powHashingData, err := hex.DecodeString(powHashingDataHex)
		assert.NoError(t, err)

		block, err := UnmarshalBlockTemplate(blockTemplateBlob, FormatBytecoin)
		assert.NoError(t, err)

		tmpl, err := MarshalBlockTemplate(block, FormatBytecoin)
		assert.NoError(t, err)
		assert.Equal(t, blockTemplateBlob, tmpl)

		block.RootBlock.CoinbaseTransaction.Extra = nil
		aux, err := BlockHeaderPreHash(block)
		assert.NoError(t, err)
		block.RootBlock.CoinbaseTransaction.Extra = ExtraMergeMiningTag(aux, 0)

		lhd, err := BlockPoWHashingData(block, FormatBytecoin)
		assert.NoError(t, err)
		assert.Equal(t, powHashingData, lhd)

		lhdR, err := BinRootBlockPoWHashingData(block.RootBlock)
		assert.NoError(t, err)
		assert.Equal(t, powHashingData, lhdR)
	}
}

func TestMergeMining(t *testing.T) {
	blobBeforeHex := "030777b53f67b1462d6c36a9a5939b6134baf8c1ea6c09a24f6ec37089835ae971a60100b4b6d7e50500000000000000000000000000000000000000000000000000000000000000000000000001010000002303210095989862283f34d7e1a2793972fed6136dd5324d0d3611e2640d1ed765674e7c011501ff0b09f8841b028859351221ac7dced1d9e3c7313111917f4d8b8fbfd478f31047a5d20253f6f0c7070238665e2c5d83d1f9d305c57a02ee4c6c854574723e43c9622f447da1422318d0c0843d02770551671a0937ed4202584ab7422872b1834066fe6e73a3fb68fb160c463ed68095f52a027c8b4dc523e8cf4a63f30302af7ff7f9e9b29b64c3c910d1cb8ce284a6b8a0f480cee4cd020260f41ed4ceb1f9a764305842d3d3a2fbca3d416a7d0b2c3c726fbf3972c3569680e497d012021c751260429b977bc451f96fc67012ee3d7ea49a5de3f162526a444b3ae6bf1180b09dc2df01029a4bc2d66f42f5f1271872d3f931fbda3f488a76715852f6ceb561080c90903080f092cbdd08029b0ec6a5daa29f053c419c8f9cfb8fabd4b69ea4b2d4f13e6b15981e42a84e3a80c089a9a2f50f028f8d9d21e58f02295d77ac79bd46071f2e6ad12bd1ebcbbbd197598e71d5ed412101a279d72b1bea175302edca7da9775a755579b3bb16bf93ac591914151cc7aafc00"
	blockBefore, err := hex.DecodeString(blobBeforeHex)
	assert.NoError(t, err)
	block, err := UnmarshalBlockTemplate(blockBefore, FormatBytecoin)
	assert.NoError(t, err)

	mmInfo := []MergeMiningItem{
		{
			Leaf: mustHashFromHex("637d52ac05c273324f9aabda53da5f28968d62b98a42520b2ae4340d5ef4f750"),
			Path: mustHashFromHex("b8e62d1e055067ce648a79a9c7e44d63a21dcecee38e4a3100061f17fe00ee98"),
		}, {
			Leaf: mustHashFromHex("0073ae45960e43f6ec445a2bd965664975d365023cf27f4e76f3cd82c08eeefc"),
			Path: mustHashFromHex("ac0634c930af9c3a12550b56f8111f8cf58b761e0a59b7e546b1f0a74d830784"),
		}, {
			Leaf: mustHashFromHex("7a25353fb95f5d7497adeb95e5f8b284d207ba67c475a43b4fc7d85259a16595"),
			Path: mustHashFromHex("f5bb1fdb7ec8d9000be4c4ae1a489632c5bf1c7a4555fbdb8ef1ed8edbcfaca5"),
		}, {
			Leaf: mustHashFromHex("b62108866a6c1dfdf8d6080410dc95966fb68095c98bfd97cdcafd84c5357829"),
			Path: mustHashFromHex("69b621d29dc719da166b5a88993542ea61cb16acb95f0ccddf90ebda21fef6e8"),
		}, {
			Leaf: mustHashFromHex("5eb3c5c614ff05122c03ab8e3b5aad5d37b4fc599c7f1a330b9fa9ecf3453c92"),
			Path: mustHashFromHex("b12bb1fe4fff196b5489577174c10c11ab838d6f8fb669bcdcac4e1b21bb4a7f"),
		}, {
			Leaf: mustHashFromHex("833adf25b74ebaad12a446f6f318b0d93aae1c9176136aa597d87778f309e362"),
			Path: mustHashFromHex("38640cd848046ea02753ed7e710c1b935f84dec76a89c980b0419dd711dde8fd"),
		}, {
			Leaf: mustHashFromHex("008f4d548b9c794770e545ae908890a6c1ba774a53204d7067d1ea42a7264da1"),
			Path: mustHashFromHex("aa5a9de6d43084a2955d7787249d3b8ab6372098bfead774642f27112208d557"),
		}, {
			Leaf: mustHashFromHex("3914f0505e6454f1586909c4e2a7f2db6918f0d691b2e410f219540981d88d9d"),
			Path: mustHashFromHex("e956747d843e6ecaeb48e0a67e7a744dbddd84614259fe7c40f8dc037c440c93"),
		}, {
			Leaf: mustHashFromHex("4bb02fc3db0e1be73e59335f993663edea1ca08672029b11d604055307573339"),
			Path: mustHashFromHex("c012520ec147944182dd8346f0490ea1bd6af50a9597e3731e6d7f0dd3506110"),
		}, {
			Leaf: mustHashFromHex("c941c96da9230caba12d24b67ce3348b0c560ed889d0f6ee5eca049951fa5b79"),
			Path: mustHashFromHex("7d2a817f8669257d69e30d95c276063e01dd017f1c7ef588cf05fdbd31598e41"),
		}, {
			Leaf: mustHashFromHex("5de3dead2ca8f7d96c1702dc572659fd625cf081179845d8db4645459a35bc57"),
			Path: mustHashFromHex("f4e79dc1a6b71ca844c080b936863b6d42c6d76914e5590bcb1798e34b83e42e"),
		}, {
			Leaf: mustHashFromHex("8eaeec5a468f9b959b6b93152633f4e1f54943357faa2f0ebce7c4a7b9f19e24"),
			Path: mustHashFromHex("ef76fe674c160c77e9212dc1640154f63c687734c2ca50e130bf7cb83f06d78b"),
		}, {
			Leaf: mustHashFromHex("f0c42832855089d14d7d5c069fe1f763bd1cc7ef7eed4d7d5874addc20e198f7"),
			Path: mustHashFromHex("2ad5157637964b566aaaeb2da01fde983c51551e6d8ad0057f3436656e061ac5"),
		}, {
			Leaf: mustHashFromHex("9d4c7789108c523963461d9048b314f4d5bbad433503ae05db47295667f86d18"),
			Path: mustHashFromHex("b79587751ef865d06a717f864bc589a4fbfa073b3c08a1510582fb89c6368181"),
		}, {
			Leaf: mustHashFromHex("08c6f4916986423f59a993d02d866ba52883e4050faa047134f94723dcedc432"),
			Path: mustHashFromHex("207eb50e1ba46a89e1d5195f4303daa93e48c204332beac5f06d9a60baf15b9b"),
		}, {
			Leaf: mustHashFromHex("e3632eccd626b8e9e7c6a681fc4ade56f57bf1dd92bab4a1213a37453a39dfca"),
			Path: mustHashFromHex("965c657632a7d3ff9f213de7fc78cafccb2381c188324347293897dc91151da8"),
		},
	}

	genesisHash := mustHashFromHex("8a6f1cb7ed7a9db4751d7b283a0482baff20567173dbfae136c9bceb188e51c4")
	leaf, err := BlockHeaderPreHash(block)
	assert.Equal(t, leaf, mustHashFromHex("95989862283f34d7e1a2793972fed6136dd5324d0d3611e2640d1ed765674e7c"))
	assert.NoError(t, err)
	mmInfo = append(mmInfo, MergeMiningItem{Leaf: leaf, Path: genesisHash})
	rootHash := FillMergeMiningBranches(mmInfo)
	assert.Equal(t, rootHash, mustHashFromHex("6b2719568368587eff0bd880c09d68c799f3ee8d3f4677d5324a0e1f647a1afc"))

	block.RootBlock = bytecoin.BinRootBlock{}
	block.RootBlock.CoinbaseTransaction.Version = 1
	block.RootBlock.BlockChainBranch = mmInfo[len(mmInfo)-1].Branch
	block.RootBlock.CoinbaseTransaction.Extra = ExtraMergeMiningTag(rootHash, byte(len(block.RootBlock.BlockChainBranch)))

	allTX := []bytecoin.Hash{getETNCoinbaseTransactionHash(block.RootBlock.CoinbaseTransaction)}
	assert.Equal(t, allTX[0], mustHashFromHex("98c55d97bff49144b93c2563ae69595f2d6222fdff4ca525bc290cbb1979c967"))

	allTX = append(allTX, mustHashFromHex("4afee12f053392949305c1db2cd25de0c655cd54e94da640d13b14cae9aff081"))
	allTX = append(allTX, mustHashFromHex("e05e607cbd2b708e4c1c574e1fdf79ae2c208900933231b7287cc4ef044676a1"))
	allTX = append(allTX, mustHashFromHex("cb1210d893c9f841d55a48b339f4562002465e733ba1fea61ec5a178c90d7da1"))
	allTX = append(allTX, mustHashFromHex("f6557e7fec5a48e4dfd6e4e701f1caf3fea588328b6749c497f6ddc122ec9e0e"))
	allTX = append(allTX, mustHashFromHex("1da99b1f988be8e1dad5ea7a41f0f982cecadb4d23707373f945f033be83e1ab"))

	block.RootBlock.TransactionCount = len(allTX)
	block.RootBlock.CoinbaseTransactionBranch = CoinbaseTreeBranch(allTX)

	blobAfterHex := "030777b53f67b1462d6c36a9a5939b6134baf8c1ea6c09a24f6ec37089835ae971a600000000000000000000000000000000000000000000000000000000000000000000000000000006bec304fa22bec2f0ca0d76e7f77be86aa2395c92921bf605e664ee81d84e9b7e4afee12f053392949305c1db2cd25de0c655cd54e94da640d13b14cae9aff08101000000230321086b2719568368587eff0bd880c09d68c799f3ee8d3f4677d5324a0e1f647a1afc9f1d3129def4f1a546ae175eadd729315a072a136bfd5f461cb4dcc596880d7e97f95f19f92a290743ccd51443aa5d8e93f004b7087e00e36503a93b9557e6b998e0fc4b43b5fdb33fef80db6f9f2359b481d2b8e1e2d8c967992b4c5b51826100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bd486824bb44e1c5fcae0df768b3297675a8488efc5ed2f36ff2046eb6c484bd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011501ff0b09f8841b028859351221ac7dced1d9e3c7313111917f4d8b8fbfd478f31047a5d20253f6f0c7070238665e2c5d83d1f9d305c57a02ee4c6c854574723e43c9622f447da1422318d0c0843d02770551671a0937ed4202584ab7422872b1834066fe6e73a3fb68fb160c463ed68095f52a027c8b4dc523e8cf4a63f30302af7ff7f9e9b29b64c3c910d1cb8ce284a6b8a0f480cee4cd020260f41ed4ceb1f9a764305842d3d3a2fbca3d416a7d0b2c3c726fbf3972c3569680e497d012021c751260429b977bc451f96fc67012ee3d7ea49a5de3f162526a444b3ae6bf1180b09dc2df01029a4bc2d66f42f5f1271872d3f931fbda3f488a76715852f6ceb561080c90903080f092cbdd08029b0ec6a5daa29f053c419c8f9cfb8fabd4b69ea4b2d4f13e6b15981e42a84e3a80c089a9a2f50f028f8d9d21e58f02295d77ac79bd46071f2e6ad12bd1ebcbbbd197598e71d5ed412101a279d72b1bea175302edca7da9775a755579b3bb16bf93ac591914151cc7aafc00"
	blockAfter, err := hex.DecodeString(blobAfterHex)

	tmpl, err := MarshalBlockTemplate(block, FormatBytecoin)
	assert.NoError(t, err)
	assert.Equal(t, blockAfter, tmpl)

	powHashingData, err := hex.DecodeString("000000000000000000000000000000000000000000000000000000000000000000000000000000dff8ec8cc4612af105da9ab9a7a2c9a6d184e8d9bdfe3e641d501afa9a9df6e006")
	assert.NoError(t, err)

	lhd, err := BlockPoWHashingData(block, FormatBytecoin)
	assert.NoError(t, err)
	assert.Equal(t, powHashingData, lhd)

	lhdR, err := BinRootBlockPoWHashingData(block.RootBlock)
	assert.NoError(t, err)
	assert.Equal(t, powHashingData, lhdR)
}

func TestPoWHashingDataEquivalence(t *testing.T) {
	blockTemplateBlobHex := "070791d38ae7053a2c76a0fd74a9e842ce84b74d524dbe35d7a4908c170de663e83e5da33363120000000001fdeb2101ffebeb2101fcd62d02502cab85091a6122f2cd32dc482788201d45aa31065b872745613e10a38817892101d25827f0a7608758150fb545353d1b9d3f850a322a8d5a63ccd2e549e4b1c611019611c6bd4afbfbaefe8bddf8831f597b7419f912f708e0be515ecf5707a55dde"
	blockTemplateBlob, err := hex.DecodeString(blockTemplateBlobHex)
	assert.NoError(t, err)

	tmpl, err := UnmarshalBlockTemplate(blockTemplateBlob, FormatElectroneum)
	assert.NoError(t, err)
	assert.Equal(t, mustHashFromHex("3a2c76a0fd74a9e842ce84b74d524dbe35d7a4908c170de663e83e5da3336312"), tmpl.PreviousBlockHash)

	powHashingData, err := hex.DecodeString("070791d38ae7053a2c76a0fd74a9e842ce84b74d524dbe35d7a4908c170de663e83e5da33363120000000030458865fa96724d1359289d082c0391520879495776d32cf4a373d3fe23e53902")
	assert.NoError(t, err)

	pow1, err := BlockPoWHashingData(tmpl, FormatElectroneum)
	assert.NoError(t, err)
	assert.Equal(t, powHashingData, pow1)

	pow2, err := BinRootBlockPoWHashingData(BlockTemplateToRootBlock(tmpl, FormatElectroneum))
	assert.NoError(t, err)
	assert.Equal(t, powHashingData, pow2)
}

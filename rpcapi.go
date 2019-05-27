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

package bytecoin

const (
	// walletd
	GetStatusMethod         = "get_status"
	GetAddressesMethod      = "get_addresses"
	GetViewKeyPairMethod    = "get_view_key_pair"
	CreateAddressesMethod   = "create_addresses"
	GetBalanceMethod        = "get_balance"
	GetUnspentsMethod       = "get_unspents"
	GetTransfersMethod      = "get_transfers"
	CreateTransactionMethod = "create_transaction"
	SendTransactionMethod   = "send_transaction"
	CreateSendproofMethod   = "create_sendproof"
	GetTransactionMethod    = "get_transaction"

	// bytecoind
	GetRawBlockMethod                  = "get_raw_block"
	GetBlockHeaderMethod               = "get_block_header"
	SyncBlocksMethod                   = "sync_blocks"
	GetRawTransactionMethod            = "get_raw_transaction"
	SyncMemPoolMethod                  = "sync_mem_pool"
	GetRandomOutputsMethod             = "get_random_outputs"
	CheckSendproofMethod               = "check_sendproof"
	GetStatisticsMethod                = "get_statistics"
	GetBlockTemplateMethodLegacy       = "getblocktemplate"
	GetBlockTemplateMethod             = "get_block_template"
	GetCurrencyIDMethodLegacy          = "getcurrencyid"
	GetCurrencyIDMethod                = "get_currency_id"
	SubmitBlockMethodLegacy            = "submitblock"
	SubmitBlockMethod                  = "submit_block"
	GetLastBlockHeaderLegacyMethod     = "getlastblockheader"
	GetBlockHeaderByHashLegacyMethod   = "getblockheaderbyhash"
	GetBlockHeaderByHeightLegacyMethod = "getblockheaderbyheight"
)

const (
	GetBalance_ADDRESS_FAILED_TO_PARSE                  = -4
	GetBalance_INVALID_HEIGHT_OR_DEPTH                  = -2
	GetBalance_ADDRESS_NOT_IN_WALLET                    = -1002
	GetUnspents_ADDRESS_FAILED_TO_PARSE                 = -4
	GetUnspents_INVALID_HEIGHT_OR_DEPTH                 = -2
	GetUnspents_ADDRESS_NOT_IN_WALLET                   = -1002
	GetTransfers_ADDRESS_FAILED_TO_PARSE                = -4
	GetTransfers_ADDRESS_NOT_IN_WALLET                  = -1002
	CreateTransaction_NOT_ENOUGH_FUNDS                  = -301
	CreateTransaction_TRANSACTION_DOES_NOT_FIT_IN_BLOCK = -302
	CreateTransaction_NOT_ENOUGH_ANONYMITY              = -303
	CreateTransaction_VIEW_ONLY_WALLET                  = -304
	CreateTransaction_INVALID_HEIGHT_OR_DEPTH           = -2
	CreateTransaction_ADDRESS_FAILED_TO_PARSE           = -4
	CreateTransaction_ADDRESS_NOT_IN_WALLET             = -1002
	SendTransaction_INVALID_TRANSACTION_BINARY_FORMAT   = -101
	SendTransaction_WRONG_OUTPUT_REFERENCE              = -102
	SendTransaction_OUTPUT_ALREADY_SPENT                = -103
	CreateSendproofResp_ADDRESS_FAILED_TO_PARSE         = -4
	GetRawBlock_HASH_NOT_FOUND                          = -4
	GetRawBlock_INVALID_HEIGHT_OR_DEPTH                 = -2
	GetBlockHeader_HASH_NOT_FOUND                       = -4
	GetBlockHeader_INVALID_HEIGHT_OR_DEPTH              = -2
	GetRawTransaction_HASH_NOT_FOUND                    = -4
	GetRandomOutputs_INVALID_HEIGHT_OR_DEPTH            = -2
	CheckSendproof_FAILED_TO_PARSE                      = -201
	CheckSendproof_NOT_IN_MAIN_CHAIN                    = -202
	CheckSendproof_WRONG_SIGNATURE                      = -203
	CheckSendproof_ADDRESS_NOT_IN_TRANSACTION           = -204
	CheckSendproof_WRONG_AMOUNT                         = -205
	GetBlockTemplate_ADDRESS_FAILED_TO_PARSE            = -4
	GetBlockTemplate_TOO_BIG_RESERVE_SIZE               = -3
	SubmitBlock_WRONG_BLOCKBLOB                         = -6
	SubmitBlock_BLOCK_NOT_ACCEPTED                      = -7
	SubmitBlockLegacy_WRONG_BLOCKBLOB                   = -6
	SubmitBlockLegacy_BLOCK_NOT_ACCEPTED                = -7
	GetBlockHeaderByHashLegacy_HASH_NOT_FOUND           = -5
	GetBlockHeaderByHeight_INVALID_HEIGHT_OR_DEPTH      = -2
)

type (
	BinTransactionInput struct { // Mix of bytecoin::InputCoinbase and bytecoin::InputKey
		Type          string   `json:"type"` // "coinbase" - coinbase, "key" - key input
		Height        int      `json:"height"`
		Amount        uint64   `json:"amount"`
		OutputIndexes []int    `json:"output_indexes,omitempty"`
		KeyImage      KeyImage `json:"key_image"`
	}

	BinTransactionOutput struct {
		Amount               uint64     `json:"amount"`
		PublicKey            PublicKey  `json:"public_key"`
		EncryptedSecret      *PublicKey `json:"encrypted_secret,omitempty"`
		EncryptedAddressType HexBlob    `json:"encrypted_address_type"` // actually single byte
		Type                 string     `json:"type"`                   // "key" - key output
	}

	BinTransactionPrefix struct {
		Version    int                    `json:"version"`
		UnlockTime uint64                 `json:"unlock_block_or_timestamp"`
		Inputs     []BinTransactionInput  `json:"inputs,omitempty"`
		Outputs    []BinTransactionOutput `json:"outputs,omitempty"`
		Extra      HexBlob                `json:"extra"`
	}

	BinTransaction struct {
		BinTransactionPrefix
		Signatures [][]string `json:"signatures"`
	}

	BinRootBlock struct {
		MajorVersion              int                  `json:"major_version"`
		MinorVersion              int                  `json:"minor_version"`
		Nonce                     HexBlob              `json:"nonce"`
		Timestamp                 uint32               `json:"timestamp"`
		PreviousBlockHash         Hash                 `json:"previous_block_hash"`
		TransactionCount          int                  `json:"transaction_count"`
		CoinbaseTransactionBranch []Hash               `json:"coinbase_transaction_branch,omitempty"`
		CoinbaseTransaction       BinTransactionPrefix `json:"coinbase_transaction"`
		BlockChainBranch          []Hash               `json:"blockchain_branch,omitempty"`
	}

	CMBranchElement struct {
		Depth int  `json:"depth"`
		Hash  Hash `json:"hash"`
	}

	BinBlockTemplate struct {
		MajorVersion      int     `json:"major_version"`
		MinorVersion      int     `json:"minor_version"`
		Nonce             HexBlob `json:"nonce"`
		Timestamp         uint32  `json:"timestamp"`
		PreviousBlockHash Hash    `json:"previous_block_hash"`

		RootBlock      BinRootBlock      `json:"root_block"`
		CMMerkleBranch []CMBranchElement `json:"cm_merkle_branch,omitempty"`

		CoinbaseTransaction BinTransaction `json:"coinbase_transaction"`
		TransactionHashes   []Hash         `json:"transaction_hashes,omitempty"`
	}

	CheckPoint struct {
		Height  int    `json:"height"`
		Hash    Hash   `json:"hash"`
		KeyID   int    `json:"key_id"`
		Counter uint64 `json:"counter"`
	}

	SignedCheckPoint struct {
		CheckPoint
		Signature string `json:"signature"`
	}

	Output struct {
		Amount      uint64 `json:"amount"`
		PK          string `json:"public_key"`
		GlobalIndex int    `json:"global_index"`
		StackIndex  int    `json:"stack_index"`

		// Added from transaction
		UnlockTime uint64 `json:"unlock_block_or_timestamp"`
		IndexInTx  int    `json:"index_in_transaction"`

		// Added from block
		Height int `json:"height"`

		// Added by wallet for recognized outputs
		KeyImage        KeyImage `json:"key_image"`
		TransactionHash Hash     `json:"transaction_hash"`
		Address         string   `json:"address"`
		IsDust          bool     `json:"dust"`
	}

	Transfer struct {
		Address string   `json:"address"`
		Amount  int64    `json:"amount"`
		Ours    bool     `json:"ours,omitempty"`
		Locked  bool     `json:"locked,omitempty"`
		Outputs []Output `json:"outputs,omitempty"`
	}

	Transaction struct {
		// fields for new transactions
		UnlockTime uint64     `json:"unlock_block_or_timestamp,omitempty"`
		Transfers  []Transfer `json:"transfers,omitempty"`
		PaymentID  Hash       `json:"payment_id,omitempty"`
		Anonymity  int        `json:"anonymity"`

		// after transaction is created
		Hash   Hash    `json:"hash"`
		Fee    uint64  `json:"fee"`
		PK     string  `json:"public_key"`
		Extra  HexBlob `json:"extra"`
		IsBase bool    `json:"coinbase"`
		Amount uint64  `json:"amount"`

		// after transaction is included in block
		BlockHeight int    `json:"block_height"`
		BlockHash   Hash   `json:"block_hash"`
		Timestamp   uint32 `json:"timestamp"`
		Size        int    `json:"size,omitempty"`
	}

	BlockHeader struct {
		MajorVersion      int     `json:"major_version"`
		MinorVersion      int     `json:"minor_version"`
		Timestamp         uint32  `json:"timestamp"`
		PreviousBlockHash Hash    `json:"previous_block_hash"`
		Nonce             uint32  `json:"nonce"`
		BinaryNonce       HexBlob `json:"binary_nonce"`

		Height                       int    `json:"height"`
		Hash                         Hash   `json:"hash"`
		Reward                       uint64 `json:"reward"`
		CumulativeDifficulty         uint64 `json:"cumulative_difficulty"`
		CumulativeDifficultyHi       uint64 `json:"cumulative_difficulty_hi"`
		Difficulty                   uint64 `json:"difficulty"`
		BaseReward                   uint64 `json:"base_reward"`
		BlockSize                    int    `json:"block_size"`
		TransactionsSize             int    `json:"transactions_size"`
		AlreadyGeneratedKeyOutputs   int    `json:"already_generated_key_outputs"`
		AlreadyGeneratedCoins        uint64 `json:"already_generated_coins"`
		AlreadyGeneratedTransactions int    `json:"already_generated_transactions"`
		SizeMedian                   int    `json:"size_median"`
		EffectiveSizeMedian          int    `json:"effective_size_median"`
		TimestampMedian              uint32 `json:"timestamp_median"`
		BlockCapacityVote            int    `json:"block_capacity_vote"`
		BlockCapacityVoteMedian      int    `json:"block_capacity_vote_median"`
		TransactionsFee              uint64 `json:"transactions_fee"`
	}

	Block struct {
		Header       BlockHeader   `json:"header"`
		Transactions []Transaction `json:"transactions,omitempty"`
	}

	Balance struct {
		Spendable                  uint64 `json:"spendable"`
		SpendableDust              uint64 `json:"spendable_dust"`
		LockedOrUnconfirmed        uint64 `json:"locked_or_unconfirmed"`
		SpendableOutputs           int    `json:"spendable_outputs"`
		SpendableDustOutputs       int    `json:"spendable_dust_outputs"`
		LockedOrUnconfirmedOutputs int    `json:"locked_or_unconfirmed_outputs"`
	}

	GetStatusReq struct {
		TopBlockHash      *Hash   `json:"top_block_hash,omitempty"`
		TxPoolVersion     *int    `json:"transaction_pool_version,omitempty"`
		OutgoingPeerCount *int    `json:"outgoing_peer_count,omitempty"`
		IncomingPeerCount *int    `json:"incoming_peer_count,omitempty"`
		LowerLevelError   *string `json:"lower_level_error,omitempty"`
	}

	GetStatusResp struct {
		TopBlockHash                   Hash   `json:"top_block_hash,omitempty"`
		TxPoolVersion                  int    `json:"transaction_pool_version,omitempty"`
		OutgoingPeerCount              int    `json:"outgoing_peer_count,omitempty"`
		IncomingPeerCount              int    `json:"incoming_peer_count,omitempty"`
		LowerLevelError                string `json:"lower_level_error,omitempty"`
		TopBlockHeight                 int    `json:"top_block_height"`
		TopKnownBlockHeight            int    `json:"top_known_block_height"`
		TopBlockDifficulty             uint64 `json:"top_block_difficulty"`
		TopBlockCumulativeDifficulty   uint64 `json:"top_block_cumulative_difficulty"`
		TopBlockCumulativeDifficultyHi uint64 `json:"top_block_cumulative_difficulty_hi"`
		RecommendedFeePerKb            uint64 `json:"recommended_fee_per_byte"`
		TopBlockTimestamp              uint32 `json:"top_block_timestamp"`
		TopBlockTimestampMedian        uint32 `json:"top_block_timestamp_median"`
		RecommendedMaxTransactionSize  int    `json:"recommended_max_transaction_size"`
	}

	GetAddressesReq struct {
		NeedSecretSpendKeys bool `json:"need_secret_spend_keys"`
		FromAddress         int  `json:"from_address"`
		MaxCount            int  `json:"max_count"`
	}

	GetAddressesResp struct {
		ViewOnly                bool     `json:"view_only"`
		WalletCreationTimestamp uint32   `json:"wallet_creation_timestamp"`
		TotalAddressCount       int      `json:"total_address_count"`
		Addresses               []string `json:"addresses,omitempty"`
		SecretSpendKeys         []string `json:"secret_spend_keys,omitempty"`
	}

	GetViewKeyPairReq struct{}

	GetViewKeyPairResp struct {
		SecretViewKey string    `json:"secret_view_key"`
		PublicViewKey PublicKey `json:"public_view_key"`
		ImportKeys    string    `json:"import_keys"`
	}

	CreateAddressesReq struct {
		SecretSpendKeys   []string `json:"secret_spend_keys,omitempty"`
		CreationTimestamp uint32   `json:"creation_timestamp"`
	}

	CreateAddressesResp struct {
		Addresses       []string `json:"addresses,omitempty"`
		SecretSpendKeys []string `json:"secret_spend_keys,omitempty"`
	}

	GetBalanceReq struct {
		Address       string `json:"address,omitempty"`
		HeightOrDepth int    `json:"height_or_depth"`
	}

	GetBalanceResp struct {
		Balance
	}

	GetUnspentsReq struct {
		Address       string `json:"address,omitempty"`
		HeightOrDepth int    `json:"height_or_depth"`
	}

	GetUnspentsResp struct {
		Spendable           []Output `json:"spendable,omitempty"`
		LockedOrUnconfirmed []Output `json:"locked_or_unconfirmed,omitempty"`
	}

	GetTransfersReq struct {
		Address                 string `json:"address,omitempty"`
		FromHeight              int    `json:"from_height"`
		ToHeight                int    `json:"to_height"`
		Forward                 bool   `json:"forward"`
		DesiredTransactionCount int    `json:"desired_transaction_count"`
	}

	GetTransfersResp struct {
		Blocks            []Block    `json:"blocks,omitempty"`
		UnlockedTransfers []Transfer `json:"unlocked_transfers,omitempty"`
		NextFromHeight    int        `json:"next_from_height"`
		NextToHeight      int        `json:"next_to_height"`
	}

	CreateTransactionReq struct {
		Transaction                     Transaction `json:"transaction"`
		SpendAddresses                  []string    `json:"spend_addresses,omitempty"`
		AnySpendAddress                 bool        `json:"any_spend_address"`
		ChangeAddress                   string      `json:"change_address,omitempty"`
		ConfirmedHeightOrDepth          int         `json:"confirmed_height_or_depth"`
		FeePerByte                      uint64      `json:"fee_per_byte"`
		Optimization                    string      `json:"optimization,omitempty"`
		SaveHistory                     bool        `json:"save_history"`
		SubtractFeeFromAmount           bool        `json:"subtract_fee_from_amount"`
		PreventConflictWithTransactions []string    `json:"prevent_conflict_with_transactions,omitempty"`
	}

	CreateTransactionResp struct {
		BinaryTransaction    HexBlob     `json:"binary_transaction,omitempty"`
		Transaction          Transaction `json:"transaction"`
		SaveHistoryError     bool        `json:"save_history_error"`
		TransactionsRequired []string    `json:"transactions_required,omitempty"`
	}

	SendTransactionReq struct {
		BinaryTransaction HexBlob `json:"binary_transaction,omitempty"`
	}

	SendTransactionResp struct {
		SendResult string `json:"send_result,omitempty"`
	}

	CreateSendproofReq struct {
		TransactionHash Hash     `json:"transaction_hash,omitempty"`
		Message         string   `json:"message,omitempty"`
		Addresses       []string `json:"addresses,omitempty"`
	}

	CreateSendproofResp struct {
		Sendproofs []string `json:"sendproofs,omitempty"`
	}

	GetTransactionReq struct {
		Hash Hash `json:"hash,omitempty"`
	}

	GetTransactionResp struct {
		Transaction Transaction `json:"transaction"`
	}

	APIRawBlock struct {
		Header             BlockHeader            `json:"header"`
		RawHeader          BinBlockTemplate       `json:"raw_header"`
		RawTransactions    []BinTransactionPrefix `json:"raw_transactions,omitempty"`
		Signatures         [][][]string           `json:"signatures,omitempty"`
		Transactions       []Transaction          `json:"transactions,omitempty"`
		OutputStackIndexes [][]int                `json:"output_stack_indexes,omitempty"`
	}

	GetRawBlockReq struct {
		Hash          Hash `json:"hash"`
		HeightOrDepth int  `json:"height_or_depth"`
	}

	GetRawBlockResp struct {
		Block        APIRawBlock `json:"block"`
		OrphanStatus bool        `json:"orphan_status"`
		Depth        int         `json:"depth"`
	}

	GetBlockHeaderReq struct {
		Hash          Hash `json:"hash"`
		HeightOrDepth int  `json:"height_or_depth"`
	}

	GetBlockHeaderResp struct {
		BlockHeader  `json:"block_header"`
		OrphanStatus bool `json:"orphan_status"`
		Depth        int  `json:"depth"`
	}

	SyncBlocksReq struct {
		SparseChain         []Hash `json:"sparse_chain,omitempty"`
		FirstBlockTimestamp uint32 `json:"first_block_timestamp"`
		MaxCount            int    `json:"max_count"`
		MaxSize             int    `json:"max_size,omitempty"`
		NeedRedundantData   bool   `json:"need_redundant_data"`
	}

	SyncBlocksResp struct {
		Blocks      []APIRawBlock `json:"blocks,omitempty"`
		StartHeight int           `json:"start_height"`
		Status      GetStatusResp `json:"status"`
	}

	GetRawTransactionReq struct {
		Hash Hash `json:"hash"`
	}

	GetRawTransactionResp struct {
		Transaction    Transaction          `json:"transaction"`
		RawTransaction BinTransactionPrefix `json:"raw_transaction"`
		Signatures     [][]string           `json:"signatures,omitempty"`
	}

	SyncMemPoolReq struct {
		KnownHashes       []Hash `json:"known_hashes,omitempty"` // should be sorted
		NeedRedundantData bool   `json:"need_redundant_data"`
	}

	SyncMemPoolResp struct {
		RemovedHashes        []Hash                 `json:"removed_hashes,omitempty"`
		AddedRawTransactions []BinTransactionPrefix `json:"added_raw_transactions,omitempty"`
		AddedSignatures      [][][]string           `json:"added_signatures,omitempty"`
		AddedTransactions    []Transaction          `json:"added_transactions,omitempty"`
		Status               GetStatusResp          `json:"status"`
	}

	GetRandomOutputsReq struct {
		Amounts                []uint64 `json:"amounts,omitempty"`
		OutputCount            int      `json:"output_count"` // anonymity + 1
		ConfirmedHeightOrDepth int      `json:"confirmed_height_or_depth"`
	}

	GetRandomOutputsResp struct {
		Outputs map[uint64][]Output `json:"outputs,omitempty"` // Not sure if json rpc can handle this in Go
	}

	Sendproof struct {
		TransactionHash Hash   `json:"transaction_hash"`
		Address         string `json:"address"`
		Amount          uint64 `json:"amount"`
		Message         string `json:"message"`
		Proof           string `json:"proof"`
	}

	CheckSendproofReq struct {
		Sendproof string `json:"sendproof"`
	}

	CheckSendproofResp struct {
		TransactionHash Hash   `json:"transaction_hash"`
		Address         string `json:"address"`
		Amount          uint64 `json:"amount"`
		Message         string `json:"message"`
		OutputIndexes   []int  `json:"output_indexes,omitempty"`
	}

	GetStatisticsReq struct{}

	GetStatisticsResp struct {
		Version          string `json:"version"`
		Platform         string `json:"platform"`
		StartTime        uint32 `json:"start_time"`
		Net              string `json:"net"`
		GenesisBlockHash Hash   `json:"genesis_block_hash"`
		PeerID           uint64 `json:"peer_id"`
		// TODO peer_list_white
		// TODO peer_list_gray
		// TODO connected_peers
		Checkpoints          []SignedCheckPoint `json:"checkpoints,omitempty"`
		UpgradeDecidedHeight int                `json:"upgrade_decided_height"`
		NodeDatabaseSize     uint64             `json:"node_database_size"`
	}

	GetBlockTemplateReq struct {
		ReserveSize            int    `json:"reserve_size,omitempty"`
		WalletAddress          string `json:"wallet_address"`
		TopBlockHash           *Hash  `json:"top_block_hash,omitempty"`           // for longpoll
		TransactionPoolVersion *int   `json:"transaction_pool_version,omitempty"` // for longpoll
	}

	GetBlockTemplateResp struct {
		Difficulty             uint64  `json:"difficulty"`
		Height                 int     `json:"height"`
		ReserveOffset          int     `json:"reserved_offset"`
		BlockTemplateBlob      HexBlob `json:"blocktemplate_blob"`
		Status                 string  `json:"status"`
		TopBlockHash           Hash    `json:"top_block_hash"`           // for longpoll
		TransactionPoolVersion int     `json:"transaction_pool_version"` // for longpoll
		CMPreHash              Hash    `json:"cm_prehash"`
		CMPath                 Hash    `json:"cm_path"`
	}

	GetCurrencyIDReq struct{}

	GetCurrencyIDResp struct {
		CurrencyIDBlob Hash `json:"currency_id_blob"`
	}

	SubmitBlockReq struct {
		BlockTemplateBlob HexBlob           `json:"blocktemplate_blob"`
		CMNonce           HexBlob           `json:"cm_nonce"`
		CMMerkleBranch    []CMBranchElement `json:"cm_merkle_branch,omitempty"`
	}

	SubmitBlockResp struct {
		BlockHeader  BlockHeader `json:"block_jeader"`
		OrphanStatus bool        `json:"orphan_status"`
		Depth        int         `json:"depth"`
	}

	SubmitBlockLegacyReq struct{}

	SubmitBlockLegacyResp struct {
		Status string `json:"status"`
	}

	BlockHeaderLegacy struct {
		BlockHeader
		OrphanStatus bool `json:"orphan_status"`
		Depth        int  `json:"depth"`
	}

	GetLastBlockHeaderLegacyReq struct{}

	GetLastBlockHeaderLegacyResp struct {
		BlockHeader BlockHeaderLegacy `json:"block_header"`
		Status      string            `json:"status"`
	}

	GetBlockHeaderByHashLegacyReq struct {
		Hash Hash `json:"hash"`
	}

	GetBlockHeaderByHashLegacyResp struct {
		BlockHeader BlockHeaderLegacy `json:"block_header"`
		Status      string            `json:"status"`
	}

	GetBlockHeaderByHeightLegacyReq struct {
		Height int `json:"height"`
	}

	GetBlockHeaderByHeightLegacyResp struct {
		BlockHeader BlockHeaderLegacy `json:"block_header"`
		Status      string            `json:"status"`
	}
)

func (p BlockHeader) Capacity() int {
	if p.BlockCapacityVoteMedian == 0 {
		return p.EffectiveSizeMedian * 2
	}
	return p.BlockCapacityVoteMedian
}

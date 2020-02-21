package main

import (
	"encoding/base64"
	"fmt"

	"github.com/algorand/go-algorand-sdk/client/algod"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/transaction"
)

//EvanCoin example
// based on purestake's submit-a-txn example

const algodAddress = "https://testnet-algorand.api.purestake.io/ps1"
const psToken = "..."

// Initalize throw-away account for this example - check that is has funds before running the program.
const mn = "..."
const ownerAddress = "..." // you could also derive this from mnemonic, I just have it hardcoded to be easier

func main() {
	// Create an algod client
	var headers []*algod.Header
	headers = append(headers, &algod.Header{"X-API-Key", psToken})
	algodClient, err := algod.MakeClientWithHeaders(algodAddress, "", headers)
	if err != nil {
		fmt.Printf("failed to make algod client: %s\n", err)
		return
	}

	// Recover private key from the mnemonic
	fromAddrPvtKey, err := mnemonic.ToPrivateKey(mn)
	if err != nil {
		fmt.Printf("error getting suggested tx params: %s\n", err)
		return
	}

	// Get the suggested transaction parameters
	txParams, err := algodClient.SuggestedParams()
	if err != nil {
		fmt.Printf("error getting suggested tx params: %s\n", err)
		return
	}

	// Make transaction
	coinTotalIssuance := uint64(1000000)
	coinDecimalsForDisplay := uint32(0) // i.e. 1 accounting unit in a transfer == 1 coin; we are not working in microCoins or anything
	accountsAreDefaultFrozen := false // if you have this coin, you can transact, the freeze manager doesn't need to unfreeze you first
	managerAddress := ownerAddress // the account issuing this is also the account in charge of managing this
	assetReserveAddress := "" // there is no asset reserve (the reserve is for informational purposes only anyways)
	addressWithFreezingPrivileges := ownerAddress // this account can blacklist others from receiving or sending assets, freezing their account
	addressWithClawbackPrivileges := ownerAddress // this account is allowed to clawback coins from others
	assetUnitName := "evancoin"
	assetName := "EvanCoin"
	assetUrl := "https://github.com/EvanJRichard"
	assetMetadataHash := "" // I am not making any hash commitments related to this, it's just a fun coin
	tx, err := transaction.MakeAssetCreateTxn(ownerAddress, txParams.Fee, txParams.LastRound, txParams.LastRound+10, nil, txParams.GenesisID, base64.StdEncoding.EncodeToString(txParams.GenesisHash),
		coinTotalIssuance, coinDecimalsForDisplay, accountsAreDefaultFrozen, managerAddress, assetReserveAddress, addressWithFreezingPrivileges, addressWithClawbackPrivileges,
		assetUnitName, assetName, assetUrl, assetMetadataHash)

	if err != nil {
		fmt.Printf("Error creating transaction: %s\n", err)
		return
	}

	// Sign the Transaction
	_, bytes, err := crypto.SignTransaction(fromAddrPvtKey, tx)
	if err != nil {
		fmt.Printf("Failed to sign transaction: %s\n", err)
		return
	}

	// Broadcast the transaction to the network
	txHeaders := append([]*algod.Header{}, &algod.Header{"Content-Type", "application/x-binary"})
	sendResponse, err := algodClient.SendRawTransaction(bytes, txHeaders...)
	if err != nil {
		fmt.Printf("failed to send transaction: %s\n", err)
		return
	}

	fmt.Printf("Transaction successful with ID: %s\n", sendResponse.TxID)
}

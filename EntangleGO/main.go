package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	. "github.com/iotaledger/iota.go/api"
	"github.com/iotaledger/iota.go/bundle"
	"github.com/iotaledger/iota.go/pow"
	"github.com/iotaledger/iota.go/transaction"
	"github.com/iotaledger/iota.go/trinary"
)

var (
	mutex = &sync.Mutex{}
)

// must be 81 trytes long and truly random
var seed = trinary.Trytes("BWBBHJXYQXXMZBNLUMALQHIBQOMWLGSPUQKKMMRWQSBBDSXGIBWZCLFEHSTMKUUDELRREXZVOGMFHJPUA")

// difficulty of the proof of work required to attach a transaction on the tangle
const mwm = 14

// how many milestones back to start the random walk from
const depth = 3
const value = uint64(0)

// can be 90 trytes long (with checksum)
const recipientAddress = ""

var endpoint = "https://potato.iotasalad.org:14265"

func main() {
	//mux
	router := mux.NewRouter()
	http.Handle("/", http.FileServer(http.Dir("./public")))
	router.HandleFunc("/upload", UploadFile).Methods("POST")

	log.Fatal(http.ListenAndServe(":8000", router))

}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// UploadFile uploads a file to the server
func UploadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	file, handle, err := r.FormFile("file")
	if err != nil {
		fmt.Fprintf(w, "%v", err)
		return
	}
	defer file.Close()

	saveFile(w, file, handle)

	//mimeType := handle.Header.Get("Content-Type")
	//switch mimeType {
	//case "image/jpeg":
	//	saveFile(w, file, handle)
	//case "image/png":
	//	saveFile(w, file, handle)
	//default:
	//	jsonResponse(w, http.StatusBadRequest, "The format file is not valid.")
	//}
}

func saveFile(w http.ResponseWriter, file multipart.File, handle *multipart.FileHeader) {
	data, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Fprintf(w, "%v", err)
		return
	}

	err = ioutil.WriteFile("./files/"+handle.Filename, data, 0666)
	if err != nil {
		fmt.Fprintf(w, "%v", err)
		return
	}
	AttachAndBroadcast(handle.Filename)

	jsonResponse(w, http.StatusCreated, "File uploaded successfully!.")
}

func jsonResponse(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprint(w, message)
}

func AttachAndBroadcast(data string) error {
	// TODO: Add logging to segment so we know what's going on.

	_, powFn := pow.GetFastestProofOfWorkImpl()

	// create a new API instance
	api, err := ComposeAPI(HTTPClientSettings{
		URI:                  endpoint,
		LocalProofOfWorkFunc: powFn,
	})
	if err != nil {
		return err
	}

	tag, err := trinary.NewTrytes("MUTSITEST")

	// Map chunks to bundle.Transfer
	trs := make([]bundle.Transfer, 1)

	addr, err := trinary.NewTrytes("GUTIESFICMRNSZWHEDQQEUABNCMP9UIUNZSKSKVUYBJSLJ9BH9RMFXIH9ZYERTUYXUIKEVKB9RZM9QLOXLY9PKPEZ9")
	if err != nil {
		return err
	}
	msg, err := trinary.NewTrytes("TESTING")
	if err != nil {
		return err
	}

	trs[0] = bundle.Transfer{
		Address: addr,
		Message: msg,
		Value:   value,
		Tag:     tag,
	}

	bdl, err := api.PrepareTransfers(seed, trs, PrepareTransfersOptions{})
	if err != nil {
		return err
	}

	transactions, err := transaction.AsTransactionObjects(bdl, nil)
	if err != nil {
		return err
	}

	transactionsToApprove, err := api.GetTransactionsToApprove(uint64(depth))
	if err != nil {
		return err
	}

	if err == nil {
		err = doPowAndBroadcast(
			transactionsToApprove.BranchTransaction,
			transactionsToApprove.TrunkTransaction,
			depth,
			transactions,
			mwm,
			powFn,
			api)
	}

	return err
}

func doPowAndBroadcast(branch trinary.Trytes, trunk trinary.Trytes, depth uint64,
	transactions []transaction.Transaction, mwm uint64, bestPow pow.ProofOfWorkFunc, api *API) error {
	var prev trinary.Trytes
	var err error

	for i := len(transactions) - 1; i >= 0; i-- {
		switch {
		case i == len(transactions)-1:
			transactions[i].TrunkTransaction = trunk
			transactions[i].BranchTransaction = branch
		default:
			transactions[i].TrunkTransaction = prev
			transactions[i].BranchTransaction = trunk
		}

		transactions[i].AttachmentTimestamp = time.Now().UnixNano() / 1000000

		// We customized this to lock here.
		mutex.Lock()
		transactionToTrytes, err := transaction.TransactionToTrytes(&transactions[i])
		if err != nil {
			return err
		}
		transactions[i].Nonce, err = bestPow(transactionToTrytes, int(mwm))

		mutex.Unlock()

		if err != nil {
			return err
		}

		prev = transaction.TransactionHash(&transactions[i])
	}

	trytes := transaction.MustTransactionsToTrytes(transactions)

	_, err = api.BroadcastTransactions(trytes...)

	if err != nil {
		errString := "FAILURE during BroadcastTransactions in lambda function: " + err.Error()
		return errors.New(errString)
	}

	_, err = api.StoreTransactions(trytes...)
	if err != nil {
		errString := "FAILURE during StoreTransactions lambda function: " + err.Error()
		return errors.New(errString)
	}

	return nil
}

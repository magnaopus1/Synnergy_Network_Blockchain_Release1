package main

import (
    "encoding/json"
    "net/http"
    "sync"

    "github.com/gorilla/mux"
    "github.com/synnergy_network/core/consensus/synnergy_consensus"
)

var (
    consensusMechanism *synnergy_consensus.SynnergyConsensusMechanism
    consensusOnce      sync.Once
)

func initConsensusMechanism() {
    consensusOnce.Do(func() {
        consensusMechanism = synnergy_consensus.NewSynnergyConsensusMechanism()
        consensusMechanism.StartConsensusProcess()
    })
}

func respondWithError(w http.ResponseWriter, code int, message string) {
    respondWithJSON(w, code, map[string]string{"error": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
    response, _ := json.Marshal(payload)
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    w.Write(response)
}

func startConsensusProcess(w http.ResponseWriter, r *http.Request) {
    initConsensusMechanism()
    respondWithJSON(w, http.StatusOK, map[string]string{"status": "consensus process started"})
}

func switchToPoW(w http.ResponseWriter, r *http.Request) {
    initConsensusMechanism()
    consensusMechanism.SwitchToPoW()
    respondWithJSON(w, http.StatusOK, map[string]string{"status": "switched to PoW"})
}

func switchToPoS(w http.ResponseWriter, r *http.Request) {
    initConsensusMechanism()
    consensusMechanism.SwitchToPoS()
    respondWithJSON(w, http.StatusOK, map[string]string{"status": "switched to PoS"})
}

func switchToPoH(w http.ResponseWriter, r *http.Request) {
    initConsensusMechanism()
    consensusMechanism.SwitchToPoH()
    respondWithJSON(w, http.StatusOK, map[string]string{"status": "switched to PoH"})
}

func calculateBlockReward(w http.ResponseWriter, r *http.Request) {
    initConsensusMechanism()
    var req struct {
        Validator synnergy_consensus.Validator `json:"validator"`
    }
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&req); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request payload")
        return
    }
    defer r.Body.Close()

    reward := consensusMechanism.CalculateBlockReward(req.Validator)
    respondWithJSON(w, http.StatusOK, map[string]*big.Int{"reward": reward})
}

func mineBlock(w http.ResponseWriter, r *http.Request) {
    initConsensusMechanism()
    var req struct {
        Transactions []string `json:"transactions"`
    }
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&req); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request payload")
        return
    }
    defer r.Body.Close()

    consensusMechanism.MineBlock(req.Transactions)
    respondWithJSON(w, http.StatusOK, map[string]string{"status": "block mined"})
}

func orderTransactions(w http.ResponseWriter, r *http.Request) {
    initConsensusMechanism()
    var req struct {
        Transactions []string `json:"transactions"`
    }
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&req); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request payload")
        return
    }
    defer r.Body.Close()

    consensusMechanism.OrderTransactions(req.Transactions)
    respondWithJSON(w, http.StatusOK, map[string]string{"status": "transactions ordered"})
}

func validateBlock(w http.ResponseWriter, r *http.Request) {
    initConsensusMechanism()
    var req struct {
        BlockHash string `json:"block_hash"`
    }
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&req); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request payload")
        return
    }
    defer r.Body.Close()

    consensusMechanism.ValidateBlock(req.BlockHash)
    respondWithJSON(w, http.StatusOK, map[string]string{"status": "block validated"})
}

func addValidator(w http.ResponseWriter, r *http.Request) {
    initConsensusMechanism()
    var req struct {
        Address string  `json:"address"`
        Stake   float64 `json:"stake"`
    }
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&req); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request payload")
        return
    }
    defer r.Body.Close()

    consensusMechanism.AddValidator(req.Address, req.Stake)
    respondWithJSON(w, http.StatusOK, map[string]string{"status": "validator added"})
}

func main() {
    router := mux.NewRouter()

    router.HandleFunc("/startConsensus", startConsensusProcess).Methods("POST")
    router.HandleFunc("/switchToPoW", switchToPoW).Methods("POST")
    router.HandleFunc("/switchToPoS", switchToPoS).Methods("POST")
    router.HandleFunc("/switchToPoH", switchToPoH).Methods("POST")
    router.HandleFunc("/calculateBlockReward", calculateBlockReward).Methods("POST")
    router.HandleFunc("/mineBlock", mineBlock).Methods("POST")
    router.HandleFunc("/orderTransactions", orderTransactions).Methods("POST")
    router.HandleFunc("/validateBlock", validateBlock).Methods("POST")
    router.HandleFunc("/addValidator", addValidator).Methods("POST")

    http.ListenAndServe(":8005", router)
}

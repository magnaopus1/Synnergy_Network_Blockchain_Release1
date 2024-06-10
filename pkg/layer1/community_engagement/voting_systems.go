package communityengagement

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "log"
    "time"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

const (
    Salt       = "secure-random-salt"
    KeyLength  = 32
)

type VoteOption struct {
    ID    string
    Title string
}

type Voter struct {
    ID       string
    Eligible bool
}

type VotingSystem struct {
    ID          string
    Title       string
    Description string
    StartDate   time.Time
    EndDate     time.Time
    Options     []VoteOption
    Votes       map[string]int
    VoterRegistry map[string]Voter
}

func NewVotingSystem(title, description string, options []VoteOption) *VotingSystem {
    return &VotingSystem{
        ID:          generateID(),
        Title:       title,
        Description: description,
        StartDate:   time.Now(),
        EndDate:     time.Now().Add(72 * time.Hour), // Default to 3 days
        Options:     options,
        Votes:       make(map[string]int),
        VoterRegistry: make(map[string]Voter),
    }
}

func (vs *VotingSystem) RegisterVoter(voter Voter) error {
    if _, exists := vs.VoterRegistry[voter.ID]; exists {
        return errors.New("voter already registered")
    }
    vs.VoterRegistry[voter.ID] = voter
    return nil
}

func (vs *VotingSystem) CastVote(voterID, optionID string) error {
    if !vs.VoterRegistry[voterID].Eligible {
        return errors.New("voter not eligible")
    }

    if time.Now().Before(vs.StartDate) || time.Now().After(vs.EndDate) {
        return errors.New("voting period is not active")
    }

    for _, option := range vs.Options {
        if option.ID == optionID {
            vs.Votes[optionID]++
            return nil
        }
    }
    return errors.New("invalid voting option")
}

func generateID() string {
    uuid := make([]byte, 16)
    _, err := rand.Read(uuid)
    if err != nil {
        log.Fatalf("Failed to generate UUID: %v", err)
    }
    return hex.EncodeToString(uuid)
}

func main() {
    options := []VoteOption{
        {ID: "opt1", Title: "Option 1"},
        {ID: "opt2", Title: "Option 2"},
    }

    votingSystem := NewVotingSystem("Community Vote", "Choose your favorite option", options)

    err := votingSystem.RegisterVoter(Voter{ID: "voter1", Eligible: true})
    if err != nil {
        log.Println(err)
    }

    err = votingSystem.CastVote("voter1", "opt1")
    if err != nil {
        log.Println(err)
    }

    log.Printf("Voting results: %+v", votingSystem.Votes)
}

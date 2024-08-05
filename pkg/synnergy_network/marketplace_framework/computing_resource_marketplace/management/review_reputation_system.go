package management

import (
	"errors"
	"sync"
	"time"
)

// Review represents a user review for a listing
type Review struct {
	ID        string
	Reviewer  string
	ListingID string
	Rating    int
	Comment   string
	CreatedAt time.Time
}

// Reputation represents a user's reputation based on reviews
type Reputation struct {
	UserID        string
	TotalReviews  int
	AverageRating float64
}

// ReviewReputationSystem manages reviews and reputation for listings
type ReviewReputationSystem struct {
	mu         sync.Mutex
	reviews    map[string]*Review
	reputations map[string]*Reputation
	nextReviewID int
}

// NewReviewReputationSystem initializes a new ReviewReputationSystem
func NewReviewReputationSystem() *ReviewReputationSystem {
	return &ReviewReputationSystem{
		reviews:    make(map[string]*Review),
		reputations: make(map[string]*Reputation),
		nextReviewID: 1,
	}
}

// AddReview adds a new review to a listing
func (rrs *ReviewReputationSystem) AddReview(reviewer, listingID string, rating int, comment string) (*Review, error) {
	rrs.mu.Lock()
	defer rrs.mu.Unlock()

	if rating < 1 || rating > 5 {
		return nil, errors.New("rating must be between 1 and 5")
	}

	id := rrs.generateReviewID()
	review := &Review{
		ID:        id,
		Reviewer:  reviewer,
		ListingID: listingID,
		Rating:    rating,
		Comment:   comment,
		CreatedAt: time.Now(),
	}

	rrs.reviews[id] = review
	rrs.updateReputation(listingID, rating)

	return review, nil
}

// GetReview retrieves a review by ID
func (rrs *ReviewReputationSystem) GetReview(id string) (*Review, error) {
	rrs.mu.Lock()
	defer rrs.mu.Unlock()

	review, exists := rrs.reviews[id]
	if !exists {
		return nil, errors.New("review not found")
	}

	return review, nil
}

// GetReviewsByListing retrieves all reviews for a given listing
func (rrs *ReviewReputationSystem) GetReviewsByListing(listingID string) ([]*Review, error) {
	rrs.mu.Lock()
	defer rrs.mu.Unlock()

	var reviews []*Review
	for _, review := range rrs.reviews {
		if review.ListingID == listingID {
			reviews = append(reviews, review)
		}
	}

	if len(reviews) == 0 {
		return nil, errors.New("no reviews found for the listing")
	}

	return reviews, nil
}

// GetReputation retrieves the reputation of a user by user ID
func (rrs *ReviewReputationSystem) GetReputation(userID string) (*Reputation, error) {
	rrs.mu.Lock()
	defer rrs.mu.Unlock()

	reputation, exists := rrs.reputations[userID]
	if !exists {
		return nil, errors.New("reputation not found for the user")
	}

	return reputation, nil
}

// updateReputation updates the reputation of a user based on a new review rating
func (rrs *ReviewReputationSystem) updateReputation(userID string, rating int) {
	reputation, exists := rrs.reputations[userID]
	if !exists {
		reputation = &Reputation{
			UserID:        userID,
			TotalReviews:  0,
			AverageRating: 0,
		}
		rrs.reputations[userID] = reputation
	}

	reputation.TotalReviews++
	reputation.AverageRating = ((reputation.AverageRating * float64(reputation.TotalReviews-1)) + float64(rating)) / float64(reputation.TotalReviews)
}

// generateReviewID generates a unique ID for a review
func (rrs *ReviewReputationSystem) generateReviewID() string {
	id := fmt.Sprintf("R-%d", rrs.nextReviewID)
	rrs.nextReviewID++
	return id
}

package identity_verification

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "sync"
    "time"
)

// IdentityVerificationManager manages the identity verification processes.
type IdentityVerificationManager struct {
    userSessions map[string]*UserSession
    mutex        sync.Mutex
}

// UserSession contains details and the current state of a user session.
type UserSession struct {
    UserID            string
    Authenticated     bool
    LastAuthenticated time.Time
    OTPSecret         string
}

// NewIdentityVerificationManager initializes a new identity verification manager.
func NewIdentityVerificationManager() *IdentityVerificationManager {
    return &IdentityVerificationManager{
        userSessions: make(map[string]*UserSession),
    }
}

// GenerateOTP generates a one-time password for a user session based on SHA-256 hashing.
func (ivm *IdentityVerificationManager) GenerateOTP(userID string) string {
    ivm.mutex.Lock()
    defer ivm.mutex.Unlock()

    session, exists := ivm.userSessions[userID]
    if !exists {
        session = &UserSession{
            UserID:        userID,
            Authenticated: false,
        }
        ivm.userSessions[userID] = session
    }

    randomBytes := make([]byte, 16)
    _, err := rand.Read(randomBytes)
    if err != nil {
        return ""
    }
    session.OTPSecret = base64.StdEncoding.EncodeToString(randomBytes)
    return session.OTPSecret
}

// VerifyOTP verifies the provided OTP against the stored secret.
func (ivm *IdentityVerificationManager) VerifyOTP(userID, otp string) bool {
    ivm.mutex.Lock()
    defer ivm.mutex.Unlock()

    session, exists := ivm.userSessions[userID]
    if !exists || session.OTPSecret != otp {
        return false
    }

    // Simulate OTP validation logic
    hash := sha256.New()
    hash.Write([]byte(otp))
    expectedHash := base64.StdEncoding.EncodeToString(hash.Sum(nil))

    return expectedHash == session.OTPSecret
}

// ContinuousAuthentication checks for continuous validation of the user identity.
func (ivm *IdentityVerificationManager) ContinuousAuthentication(userID string) bool {
    ivm.mutex.Lock()
    defer ivm.mutex.Unlock()

    session, exists := ivm.userSessions[userID]
    if !exists {
        return false
    }

    // Check if the last authentication was within the acceptable time frame
    if time.Since(session.LastAuthenticated) > 30*time.Minute {
        session.Authenticated = false
        return false
    }

    return session.Authenticated
}


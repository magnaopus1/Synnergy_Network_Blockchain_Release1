package storage

import (
    "database/sql"
    "errors"
    "log"
    "sync"
    "fmt"

    _ "github.com/mattn/go-sqlite3"
    "synnergy_network_blockchain/pkg/synnergy_network/cryptography/encryption"
    "synnergy_network_blockchain/pkg/synnergy_network/cryptography/hash"
    "synnergy_network_blockchain/pkg/synnergy_network/cryptography/keys"
    "synnergy_network_blockchain/pkg/synnergy_network/cryptography/signature"
    "synnergy_network_blockchain/pkg/synnergy_network/compliance/audit_trails"
    "synnergy_network_blockchain/pkg/synnergy_network/compliance/data_protection"
    "synnergy_network_blockchain/pkg/synnergy_network/compliance/fraud_detection_and_risk_management"
)

type Database struct {
    db     *sql.DB
    mutex  sync.Mutex
    dbPath string
}

const (
    createTokenTable = `CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT NOT NULL UNIQUE,
        balance INTEGER NOT NULL
    );`
    createTransactionTable = `CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        amount INTEGER NOT NULL,
        signature TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );`
    createAuditLogTable = `CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL,
        details TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );`
)

func NewDatabase(tokenID, dbPath string) *Database {
    dbFile := fmt.Sprintf("%s_%s.db", tokenID, dbPath)
    db, err := sql.Open("sqlite3", dbFile)
    if err != nil {
        log.Fatal(err)
    }

    database := &Database{
        db:     db,
        dbPath: dbFile,
    }

    database.createTables()

    return database
}

func (d *Database) createTables() {
    d.mutex.Lock()
    defer d.mutex.Unlock()

    statements := []string{createTokenTable, createTransactionTable, createAuditLogTable}
    for _, stmt := range statements {
        _, err := d.db.Exec(stmt)
        if err != nil {
            log.Fatal(err)
        }
    }
}

func (d *Database) AddToken(address string, initialBalance int) error {
    d.mutex.Lock()
    defer d.mutex.Unlock()

    hashAddress := hash.HashAddress(address)
    _, err := d.db.Exec("INSERT INTO tokens (address, balance) VALUES (?, ?)", hashAddress, initialBalance)
    if err != nil {
        return err
    }

    d.logAudit("AddToken", "Address: "+address+", Balance: "+string(initialBalance))
    return nil
}

func (d *Database) GetBalance(address string) (int, error) {
    d.mutex.Lock()
    defer d.mutex.Unlock()

    hashAddress := hash.HashAddress(address)
    var balance int
    err := d.db.QueryRow("SELECT balance FROM tokens WHERE address = ?", hashAddress).Scan(&balance)
    if err != nil {
        return 0, err
    }

    return balance, nil
}

func (d *Database) Transfer(sender, receiver string, amount int, senderKey keys.PrivateKey) error {
    d.mutex.Lock()
    defer d.mutex.Unlock()

    senderBalance, err := d.GetBalance(sender)
    if err != nil {
        return err
    }
    if senderBalance < amount {
        return errors.New("insufficient balance")
    }

    receiverBalance, err := d.GetBalance(receiver)
    if err != nil {
        return err
    }

    newSenderBalance := senderBalance - amount
    newReceiverBalance := receiverBalance + amount

    tx, err := d.db.Begin()
    if err != nil {
        return err
    }

    _, err = tx.Exec("UPDATE tokens SET balance = ? WHERE address = ?", newSenderBalance, hash.HashAddress(sender))
    if err != nil {
        tx.Rollback()
        return err
    }

    _, err = tx.Exec("UPDATE tokens SET balance = ? WHERE address = ?", newReceiverBalance, hash.HashAddress(receiver))
    if err != nil {
        tx.Rollback()
        return err
    }

    sig, err := signature.SignTransaction(senderKey, sender, receiver, amount)
    if err != nil {
        tx.Rollback()
        return err
    }

    _, err = tx.Exec("INSERT INTO transactions (sender, receiver, amount, signature) VALUES (?, ?, ?, ?)",
        hash.HashAddress(sender), hash.HashAddress(receiver), amount, sig)
    if err != nil {
        tx.Rollback()
        return err
    }

    err = tx.Commit()
    if err != nil {
        return err
    }

    d.logAudit("Transfer", "Sender: "+sender+", Receiver: "+receiver+", Amount: "+string(amount))
    return nil
}

func (d *Database) logAudit(event, details string) {
    _, err := d.db.Exec("INSERT INTO audit_logs (event, details) VALUES (?, ?)", event, details)
    if err != nil {
        log.Println("Failed to log audit event:", err)
    }
}

func (d *Database) Close() error {
    return d.db.Close()
}

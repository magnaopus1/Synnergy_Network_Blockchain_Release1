package syn2400

import (
    "database/sql"
    "fmt"
    "log"
    _ "github.com/mattn/go-sqlite3" // Use the SQLite driver
)

type DBStorage struct {
    db *sql.DB
}

func NewDBStorage(dataSourceName string) *DBStorage {
    db, err := sql.Open("sqlite3", dataSourceName)
    if err != nil {
        log.Fatalf("Unable to connect to database: %v", err)
    }
    return &DBStorage{db: db}
}

func (storage *DBStorage) InsertToken(token DataToken) error {
    insertSQL := `INSERT INTO data_tokens (token_id, owner, data_hash, description, access_rights, created_at, updated_at, price, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`
    _, err := storage.db.Exec(insertSQL, token.TokenID, token.Owner, token.DataHash, token.Description, token.AccessRights, token.CreatedAt, token.UpdatedAt, token.Price, token.Active)
    if err != nil {
        return fmt.Errorf("failed to insert token: %v", err)
    }
    return nil
}

func (storage *DBStorage) UpdateToken(token DataToken) error {
    updateSQL := `UPDATE data_tokens SET owner = ?, data_hash = ?, description = ?, access_rights = ?, updated_at = ?, price = ?, active = ? WHERE token_id = ?;`
    _, err := storage.db.Exec(updateSQL, token.Owner, token.DataHash, token.Description, token.AccessRights, token.UpdatedAt, token.Price, token.Active, token.TokenID)
    if err != nil {
        return fmt.Errorf("failed to update token: %v", err)
    }
    return nil
}

func (storage *DBStorage) DeleteToken(tokenID string) error {
    deleteSQL := `DELETE FROM data_tokens WHERE token_id = ?;`
    _, err := storage.db.Exec(deleteSQL, tokenID)
    if err != nil {
        return fmt.Errorf("failed to delete token: %v", err)
    }
    return nil
}

func (storage *DBStorage) GetToken(tokenID string) (DataToken, error) {
    selectSQL := `SELECT token_id, owner, data_hash, description, access_rights, created_at, updated_at, price, active FROM data_tokens WHERE token_id = ?;`
    row := storage.db.QueryRow(selectSQL, tokenID)
    var token DataToken
    err := row.Scan(&token.TokenID, &token.Owner, &token.DataHash, &token.Description, &token.AccessRights, &token.CreatedAt, &token.UpdatedAt, &token.Price, &token.Active)
    if err != nil {
        if err == sql.ErrNoRows {
            return DataToken{}, fmt.Errorf("no token found with ID %s", tokenID)
        }
        return DataToken{}, fmt.Errorf("failed to retrieve token: %v", err)
    }
    return token, nil
}

func (storage *DBStorage) Close() error {
    return storage.db.Close()
}

package auth

import (
	"42tokyo-road-to-dena-server/domain"
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// ============================================================================
// SQL関連だからinfrastructure層だ！ って思ったけど「cannot define new methods on non-local type 」
// となる　どうすればいいのやら、と思ったけどdomainにインターフェースを置くことで解決
// ============================================================================

type RefreshTokenStore struct {
	db *sqlx.DB
}

// ハッシュでリフレッシュトークンを取得
func (st *RefreshTokenStore) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	var token domain.RefreshToken
	query := `
		SELECT id, user_id, token_hash, expires_at, revoked_at, created_at, updated_at, deleted_at
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND deleted_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
	`
	err := st.db.GetContext(ctx, &token, query, tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &token, nil
}

// リフレッシュトークンの保存
func (st *RefreshTokenStore) Create(ctx context.Context, token *domain.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := st.db.ExecContext(ctx, query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.ExpiresAt,
		token.CreatedAt,
		token.UpdatedAt,
	)
	return err
}

// ハッシュでリフレッシュトークンを失効
func (st *RefreshTokenStore) RevokeByTokenHash(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = NOW(), updated_at = NOW()
		WHERE token_hash = $1
		  AND deleted_at IS NULL
		  AND revoked_at IS NULL
	`
	_, err := st.db.ExecContext(ctx, query, tokenHash)
	return err
}

// ユーザーIDの全リフレッシュトークンを失効
func (st *RefreshTokenStore) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = NOW(), updated_at = NOW()
		WHERE user_id = $1
		  AND deleted_at IS NULL
		  AND revoked_at IS NULL
	`
	_, err := st.db.ExecContext(ctx, query, userID)
	return err
}

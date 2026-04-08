package domain

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// コンテキストで使用するキー
type contextKey string

const UserIDKey contextKey = "userID"

// エラー定数
var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrInvalidInput = errors.New("invalid input")
	ErrInternal     = errors.New("internal server error")
)

// リクエスト/レスポンス型
type AuthLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignupRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token,omitempty"`
}

type AuthTokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// エンティティ
type RefreshToken struct {
	ID        uuid.UUID    `db:"id"`
	UserID    uuid.UUID    `db:"user_id"`
	TokenHash string       `db:"token_hash"`
	ExpiresAt time.Time    `db:"expires_at"`
	RevokedAt *time.Time   `db:"revoked_at"`
	CreatedAt time.Time    `db:"created_at"`
	UpdatedAt time.Time    `db:"updated_at"`
	DeletedAt sql.NullTime `db:"deleted_at"`
}

type AuthConfig struct {
	JWTSecret    string
	JWTIssuer    string
	JWTAudience  string
	AccessTTL    time.Duration
	RefreshTTL   time.Duration
	CookieDomain string
	CookieSecure bool
}

// JWTクレーム
type AuthClaims struct {
	UserID uuid.UUID `json:"sub"`
	jwt.RegisteredClaims
}

// リフレッシュトークンのインターフェース
type RefreshTokenRepository interface {
	Create(ctx context.Context, token *RefreshToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeByTokenHash(ctx context.Context, tokenHash string) error
	RevokeByUserID(ctx context.Context, userId uuid.UUID) error
}

// auth関連のインターフェース
// なんでバリデーションするんや...? 認証の時かな..?
type AuthBundleRepository interface {
	GenerateAccessToken(userID uuid.UUID) (string, error)
	ValidateAccessToken(tokenString string) (*AuthClaims, error)
	GenerateRefreshToken(ctx context.Context, userID uuid.UUID) (string, error)
	ValidateRefreshToken(ctx context.Context, tokenString string) (*RefreshToken, error)
	RotateRefreshToken(ctx context.Context, oldTokenString string) (string, error)
}

// ============================================================================
// domain層に既存のレシーバで実装された判定を入れてもいいのかがわからないが今回は
// 調べてみたところ　型自身の整合性・状態判定(有効期限、執行済み)の場合はモデルの責務
// らしくここに実装を移しました
// ============================================================================

// リフレッシュトークンの有効期限切れ判定
func (r *RefreshToken) IsExpired() bool {
	return r.ExpiresAt.Before(time.Now())
}

// リフレッシュトークンの失効済み判定
func (r *RefreshToken) IsRevoked() bool {
	return r.RevokedAt != nil
}

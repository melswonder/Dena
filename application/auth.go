package application

import (
	"42tokyo-road-to-dena-server/domain"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// refreshTokenStoreだと今回のクリーンアーキテクチャ的に拡張性が少ないため
// refreshTokenRepositoryという名前のインターフェースに変更　CRUD的に良い
type AuthBundle struct {
	cfg                    *domain.AuthConfig
	refreshTokenRepository domain.RefreshTokenRepository
}

// コンテキストからユーザーIDを取得
func GetUserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value(domain.UserIDKey).(uuid.UUID)
	return userID, ok
}

// コンテキストにユーザーIDを設定
func SetUserIDInContext(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, domain.UserIDKey, userID)
}


// パスワードハッシュ生成
func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

// パスワード検証
func CheckPassword(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// アクセストークン生成
func (a *AuthBundle) GenerateAccessToken(userID uuid.UUID) (string, error) {
	now := time.Now()
	claims := domain.AuthClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(a.cfg.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    a.cfg.JWTIssuer,
			Audience:  []string{a.cfg.JWTAudience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(a.cfg.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("%w: failed to sign token: %v", domain.ErrInternal, err)
	}

	return tokenString, nil
}

// アクセストークン検証
func (a *AuthBundle) ValidateAccessToken(tokenString string) (*domain.AuthClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AuthClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: unexpected signing method: %v", domain.ErrUnauthorized, token.Header["alg"])
		}
		return []byte(a.cfg.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, domain.ErrUnauthorized
	}

	claims, ok := token.Claims.(*domain.AuthClaims)
	if !ok {
		return nil, domain.ErrUnauthorized
	}

	// Issuer検証
	if claims.Issuer != a.cfg.JWTIssuer {
		return nil, domain.ErrUnauthorized
	}

	// Audience検証
	validAudience := false
	for _, aud := range claims.Audience {
		if aud == a.cfg.JWTAudience {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return nil, domain.ErrUnauthorized
	}

	return claims, nil
}

// リフレッシュトークン生成
func (a *AuthBundle) GenerateRefreshToken(ctx context.Context, userID uuid.UUID) (string, error) {
	// ランダムトークン生成
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("%w: failed to generate random token: %v", domain.ErrInternal, err)
	}
	tokenString := hex.EncodeToString(tokenBytes)

	// ハッシュ化
	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	// DB保存
	refreshToken := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(a.cfg.RefreshTTL),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := a.refreshTokenRepository.Create(ctx, refreshToken); err != nil {
		return "", fmt.Errorf("%w: failed to save refresh token: %v", domain.ErrInternal, err)
	}

	return tokenString, nil
}

// リフレッシュトークン検証
func (a *AuthBundle) ValidateRefreshToken(ctx context.Context, tokenString string) (*domain.RefreshToken, error) {
	// ハッシュ化
	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	// DB検索
	token, err := a.refreshTokenRepository.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, domain.ErrUnauthorized
	}

	if token.IsExpired() {
		return nil, domain.ErrUnauthorized
	}

	if token.IsRevoked() {
		return nil, domain.ErrUnauthorized
	}

	return token, nil
}

// リフレッシュトークンローテーション
func (a *AuthBundle) RotateRefreshToken(ctx context.Context, oldTokenString string) (string, error) {
	// 旧トークン検証
	oldToken, err := a.ValidateRefreshToken(ctx, oldTokenString)
	if err != nil {
		return "", err
	}

	// 旧トークン失効
	hash := sha256.Sum256([]byte(oldTokenString))
	tokenHash := hex.EncodeToString(hash[:])
	if err := a.refreshTokenRepository.RevokeByTokenHash(ctx, tokenHash); err != nil {
		return "", fmt.Errorf("%w: failed to revoke old token: %v", domain.ErrInternal, err)
	}

	// 新トークン生成
	newToken, err := a.GenerateRefreshToken(ctx, oldToken.UserID)
	if err != nil {
		return "", fmt.Errorf("%w: failed to generate new token: %v", domain.ErrInternal, err)
	}

	return newToken, nil
}

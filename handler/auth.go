package handler

import (
	"42tokyo-road-to-dena-server/domain"
	"context"
	"net/http"
	"strings"
)

// AuthRequired はアクセストークンを検証し、context に userID を注入する
func (h *Handler) AuthRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := h.extractTokenFromRequest(r)

		if token == "" {
			h.respondError(w, domain.ErrUnauthorized, http.StatusUnauthorized)
			return
		}

		if h.authBundleRepository == nil {
			h.respondError(w, domain.ErrUnauthorized, http.StatusUnauthorized)
			return
		}

		claims, err := h.authBundleRepository.ValidateAccessToken(token)
		if err != nil {
			h.respondError(w, domain.ErrUnauthorized, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), domain.UserIDKey, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Authorization ヘッダまたは Cookie からトークンを取得する
func (h *Handler) extractTokenFromRequest(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1]
		}
	}

	cookie, err := r.Cookie("access_token")
	if err == nil {
		return cookie.Value
	}

	return ""
}

// Cookie設定
func SetAuthCookies(w http.ResponseWriter, accessToken, refreshToken string, cfg *domain.AuthConfig) {
	// アクセストークンCookie
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Domain:   cfg.CookieDomain,
		MaxAge:   int(cfg.AccessTTL.Seconds()),
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	// リフレッシュトークンCookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		Domain:   cfg.CookieDomain,
		MaxAge:   int(cfg.RefreshTTL.Seconds()),
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

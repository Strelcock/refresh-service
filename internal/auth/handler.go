package auth

import (
	"auth/configs"
	_ "auth/docs"
	"auth/internal/models"
	"auth/pkg/generator"
	"auth/pkg/jsonconv"
	"auth/pkg/jwt"
	"auth/pkg/middleware"
	"auth/pkg/notification"
	"auth/pkg/requests"
	"net/http"
	"strings"
	"time"

	httpSwagger "github.com/swaggo/http-swagger"
)

type AuthHandler struct {
	*configs.Config
	Service *AuthService
}

type AuthHandlerDeps struct {
	*configs.Config
	Service *AuthService
}

func NewAuthHandler(router *http.ServeMux, deps AuthHandlerDeps) {
	handler := &AuthHandler{
		Config:  deps.Config,
		Service: deps.Service,
	}

	router.HandleFunc("/tokens/{id}", handler.CreateToken())
	router.Handle("POST /tokens/refresh", middleware.Authentificator(handler.Refresh(), handler.Config))
	router.Handle("/tokens", middleware.Authentificator(handler.GetID(), handler.Config))
	router.Handle("DELETE /tokens/{id}", middleware.Authentificator(handler.Unauthorize(), handler.Config))
	router.HandleFunc("/swagger/", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8080/swagger/doc.json"),
	))

}

// @Summary Create pair of tokens
// @Description Creates access and refresh tokens
// @Tags tokens
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} AuthResponse
// @Failure 500 {object} string
// @Router /tokens/{id} [get]
func (ah *AuthHandler) CreateToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := r.PathValue("id")

		refreshToken, access, err := GenerateTokens(r, uid, *ah.Config)

		unhased := refreshToken.Hash
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = ah.Service.Create(refreshToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonconv.Json(w, AuthResponse{
			Access:  access,
			Refresh: unhased,
		}, http.StatusOK)
	}
}

// @Summary Refresh a pair of tokens
// @Description Refreshes access and refresh tokens. You can only refresh tokens that were returned together, after resfresh old pair is invalid
// @Description If User-Agent from current request is unlike User-Agent from last request you will be unauthed.
// @Tags tokens
// @Security AuthKey
// @Accept json
// @Produce json
// @Param old_token body RefreshRequest true "old refresh token"
// @Param User-Agent header string false "User-Agent"
// @Param X-Forwarded-For header string false "User IP-adress"
// @Success 200 {object} AuthResponse
// @Failure 400 {object} string
// @Failure 401 {object} string
// @Failure 500 {object} string
// @Router /tokens/refresh [post]
func (ah *AuthHandler) Refresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := requests.Decode[RefreshRequest](r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		jti := r.Context().Value(middleware.JTIKey).(string)
		uid := r.Context().Value(middleware.UidKey).(string)
		token, err := ah.Service.CheckRefresh(jti, body.OldToken)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		//chek user-agent
		if token.UserAgent != r.Header.Get("User-Agent") {
			ah.Service.Delete(uid)
			http.Error(w, "wrong user-agent", http.StatusUnauthorized)
			return
		}

		//check ip
		userIPs := r.Header.Get("X-Forwarded-For")
		ip := strings.Split(strings.TrimSpace(userIPs), ",")[0]
		if token.IP != ip {
			go notification.NotifyWebhook(uid, token.IP, ip)
		}

		//refresh
		refreshToken, access, err := GenerateTokens(r, uid, *ah.Config)

		unhashed := refreshToken.Hash
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = ah.Service.Create(refreshToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonconv.Json(w, AuthResponse{
			Access:  access,
			Refresh: unhashed,
		}, http.StatusCreated)
	}
}

// @Summary Get user ID
// @Description Returns user's id from access token
// @Tags tokens
// @Security AuthKey
// @Produce json
// @Success 200 {object} UidResponse
// @Failure 401 {object} string
// @Router /tokens [get]
func (ah *AuthHandler) GetID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := r.Context().Value(middleware.UidKey).(string)
		jti := r.Context().Value(middleware.JTIKey).(string)

		_, err := ah.Service.Repo.GetByJTI(jti)

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		result := UidResponse{
			UID: uid,
		}
		jsonconv.Json(w, result, http.StatusOK)
	}
}

// @Summary Unauthorize user
// @Description Deletes all user data from DB
// @Tags tokens
// @Security AuthKey
// @Param id path string true "User ID"
// @Success 200 {object} string
// @Failure 500 {object} string
// @Router /tokens/{id} [delete]
func (ah *AuthHandler) Unauthorize() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := r.PathValue("id")
		err := ah.Service.Delete(uid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}
}

func GenerateTokens(r *http.Request, uid string, conf configs.Config) (*models.Refresh, string, error) {
	refresh := generator.Token()
	jti := generator.JTI()

	access, err := jwt.NewJWT(conf.Secret).Create(jwt.JWTData{
		Sub: uid,
		Jti: jti,
		Exp: time.Now().Unix() + 5*int64(time.Minute),
	})

	if err != nil {
		return nil, "", err
	}

	userAgent, userIPs := r.Header.Get("User-Agent"), r.Header.Get("X-Forwarded-For")
	ip := strings.Split(strings.TrimSpace(userIPs), ",")[0]

	refreshToken := &models.Refresh{
		UID:       uid,
		Hash:      refresh,
		UserAgent: userAgent,
		IP:        ip,
		Jti:       jti,
	}
	return refreshToken, access, nil
}

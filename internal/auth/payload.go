package auth

type RefreshRequest struct {
	OldToken string `json:"old_token"`
}

type AuthResponse struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type UidResponse struct {
	UID string `json:"user_id"`
}

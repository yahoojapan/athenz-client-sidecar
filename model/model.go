package model

type HCCRequest struct {
	AppID string `json:"app_id"`
}

type UDBRequest struct {
	AppID   string `json:"app_id"`
	NCookie string `json:"n_cookie"`
	TCookie string `json:"t_cookie"`
	KeyID   string `json:"key_id"`
	KeyData string `json:"key_data"`
}

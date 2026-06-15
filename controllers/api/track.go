package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"

	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/models"
)

type clickEventRequest struct {
	UUID      string `json:"uuid"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

// evilginxWebhookRequest is the payload EvilGinx POSTs to the webhook URL
// when credentials are captured. The UUID is embedded in LandingURL as the
// gp_uuid query parameter, which is appended to every phishing link sent by
// GoPhish so that captures can be correlated with campaign results.
type evilginxWebhookRequest struct {
	SessionID  string `json:"session_id"`
	Phishlet   string `json:"phishlet"`
	LandingURL string `json:"landing_url"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	RemoteAddr string `json:"remote_addr"`
	UserAgent  string `json:"useragent"`
}

// TrackClickByUUID records a link-clicked event for the result identified by
// the given UUID. Called by the external redirector (ams-maritime) after the
// Turnstile challenge passes and before the user is forwarded to the login
// flow, so automated mail-scanner hits are excluded from click counts.
func (as *Server) TrackClickByUUID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	var req clickEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid request body"}, http.StatusBadRequest)
		return
	}

	if req.UUID == "" {
		JSONResponse(w, models.Response{Success: false, Message: "uuid is required"}, http.StatusBadRequest)
		return
	}

	result, err := models.GetResultByUUID(req.UUID)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Result not found"}, http.StatusNotFound)
		return
	}

	c, err := models.GetCampaign(result.CampaignId, result.UserId)
	if err != nil {
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Campaign not found"}, http.StatusInternalServerError)
		return
	}
	if c.Status == models.CampaignComplete {
		JSONResponse(w, models.Response{Success: false, Message: "Campaign is complete"}, http.StatusGone)
		return
	}

	details := models.EventDetails{
		Payload: url.Values{},
		Browser: map[string]string{
			"address":    req.IP,
			"user-agent": req.UserAgent,
		},
	}

	if err := result.HandleClickedLink(details); err != nil {
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Failed to record event"}, http.StatusInternalServerError)
		return
	}

	JSONResponse(w, models.Response{Success: true, Message: "Click recorded"}, http.StatusOK)
}

// TrackCredentialByUUID records a credential-submitted event for the result
// identified by the given UUID. Called by EvilGinx via its webhook after
// credentials are captured, so GoPhish campaign results show the full chain:
// email sent → opened → clicked → credentials submitted.
//
// EvilGinx posts its native webhook format; the GoPhish UUID is extracted from
// the gp_uuid query parameter embedded in the LandingURL field.
func (as *Server) TrackCredentialByUUID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	var req evilginxWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid request body"}, http.StatusBadRequest)
		return
	}

	// Extract the GoPhish UUID from the gp_uuid query parameter that is
	// appended to every phishing link, e.g. ?gp_uuid=<rid>&...
	uuid := ""
	if req.LandingURL != "" {
		if parsed, err := url.Parse(req.LandingURL); err == nil {
			uuid = parsed.Query().Get("gp_uuid")
		}
	}
	if uuid == "" {
		JSONResponse(w, models.Response{Success: false, Message: "gp_uuid not found in landing_url"}, http.StatusBadRequest)
		return
	}

	result, err := models.GetResultByUUID(uuid)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Result not found"}, http.StatusNotFound)
		return
	}

	c, err := models.GetCampaign(result.CampaignId, result.UserId)
	if err != nil {
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Campaign not found"}, http.StatusInternalServerError)
		return
	}
	if c.Status == models.CampaignComplete {
		JSONResponse(w, models.Response{Success: false, Message: "Campaign is complete"}, http.StatusGone)
		return
	}

	// Strip port from remote_addr if present (EvilGinx includes it).
	ip := req.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	payload := url.Values{}
	if req.Username != "" {
		payload.Set("username", req.Username)
	}
	if req.Password != "" {
		payload.Set("password", req.Password)
	}

	details := models.EventDetails{
		Payload: payload,
		Browser: map[string]string{
			"address":    ip,
			"user-agent": req.UserAgent,
		},
	}

	if err := result.HandleFormSubmit(details); err != nil {
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Failed to record event"}, http.StatusInternalServerError)
		return
	}

	JSONResponse(w, models.Response{Success: true, Message: "Credential recorded"}, http.StatusOK)
}

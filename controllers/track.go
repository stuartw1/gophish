package controllers

import (
	"net/http"
	"strings"

	ctx "github.com/gophish/gophish/context"
	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/models"
)

// TrackEmailOpen handles the email open-tracking pixel on the admin server.
// It reuses the same ?rid= mechanism as the phishing server's /track endpoint
// so that campaigns whose URL points at the admin server record email opens
// correctly even when the phishing server is not running.
func TrackEmailOpen(w http.ResponseWriter, r *http.Request) {
	r, err := setupContext(r)
	if err != nil {
		if err != ErrInvalidRequest && err != ErrCampaignComplete {
			log.Error(err)
		}
		http.ServeFile(w, r, "static/images/pixel.png")
		return
	}

	// Preview requests — just return the pixel.
	if _, ok := ctx.Get(r, "result").(models.EmailRequest); ok {
		http.ServeFile(w, r, "static/images/pixel.png")
		return
	}

	rs := ctx.Get(r, "result").(models.Result)
	rid := ctx.Get(r, "rid").(string)
	d := ctx.Get(r, "details").(models.EventDetails)

	if strings.HasSuffix(rid, TransparencySuffix) {
		http.ServeFile(w, r, "static/images/pixel.png")
		return
	}

	if err := rs.HandleEmailOpened(d); err != nil {
		log.Error(err)
	}
	http.ServeFile(w, r, "static/images/pixel.png")
}

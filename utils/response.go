package utils

import (
	"context"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
)

const (
	ContentType = "application/json"
	Charset     = "utf-8"
)

type ErrResp struct {
	APIErr *APIError `json:"error"`
}

type APIError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Status  string `json:"status"`
}

func (e *APIError) Error() string {
	return e.Message
}

func RespondOk(w http.ResponseWriter, code int, data interface{}) {

	// Add content type header to the response
	w.Header().Add("Content-Type", fmt.Sprintf("%s; charset=%s", ContentType, Charset))

	//Add status code
	w.WriteHeader(code)

	// convert to bytes
	rb, _ := json.MarshalIndent(data, "", " ")

	//Write the response
	w.Write(rb)
}

func RespondError(ctx context.Context, w http.ResponseWriter, err error) {

	apiErr := err.(*APIError)

	errResp := ErrResp{APIErr: apiErr}

	// Add content type header to the response
	w.Header().Add("Content-Type", fmt.Sprintf("%s; charset=%s", ContentType, Charset))

	//Add status code
	w.WriteHeader(apiErr.Code)

	//log the APIError
	log.WithFields(
		log.Fields{
			"trace_id": ctx.Value("trace_id"),
			"type":     "service_log",
			"code":     apiErr.Code,
			"status":   apiErr.Status,
		},
	).Error(apiErr.Message)

	// Write the response
	errData, _ := json.MarshalIndent(errResp, "", " ")
	w.Write(errData)
}

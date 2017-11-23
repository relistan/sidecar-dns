package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Nitro/sidecar/receiver"
	"github.com/Nitro/sidecar/service"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const (
	RELOAD_BUFFER = 250
)

type ApiStatus struct {
	Message        string           `json:"message"`
	LastChanged    time.Time        `json:"last_changed"`
	ServiceChanged *service.Service `json:"last_service_changed"`
}

// The health check endpoint.
func healthHandler(response http.ResponseWriter, req *http.Request, rcvr *receiver.Receiver) {
	defer req.Body.Close()
	response.Header().Set("Content-Type", "application/json")

	rcvr.StateLock.Lock()
	defer rcvr.StateLock.Unlock()

	var lastChanged time.Time
	if rcvr.CurrentState != nil {
		lastChanged = rcvr.CurrentState.LastChanged
	}

	message, _ := json.Marshal(ApiStatus{
		Message:        "Healthy!",
		LastChanged:    lastChanged,
		ServiceChanged: rcvr.LastSvcChanged,
	})

	response.Write(message)
}

// Returns the currently stored state as a JSON blob
func stateHandler(response http.ResponseWriter, req *http.Request, rcvr *receiver.Receiver) {
	defer req.Body.Close()
	response.Header().Set("Content-Type", "application/json")

	if rcvr.CurrentState == nil {
		message, _ := json.Marshal(receiver.ApiErrors{[]string{"No currently stored state"}})
		response.WriteHeader(http.StatusInternalServerError)
		response.Write(message)
		return
	}

	if req.FormValue("byservice") == "true" {
		services, err := json.Marshal(rcvr.CurrentState.ByService())
		if err != nil {
			http.Error(response, "Can't marshal state in service format!", 500)
			return
		}
		response.Write(services)
		return
	}

	response.Write(rcvr.CurrentState.Encode())
}

// Wrap a handler that needs a receiver into a standard http.HandlerFunc
func wrapHandler(handler func(http.ResponseWriter, *http.Request, *receiver.Receiver), rcvr *receiver.Receiver) http.HandlerFunc {
	return func(response http.ResponseWriter, req *http.Request) {
		handler(response, req, rcvr)
	}
}

// Start the HTTP server and begin handling requests. This is a
// blocking call.
func serveHttp(listenIp string, listenPort int, rcvr *receiver.Receiver) {
	listenStr := fmt.Sprintf("%s:%d", listenIp, listenPort)

	log.Infof("Starting up on %s", listenStr)
	router := mux.NewRouter()

	updateWrapped := wrapHandler(receiver.UpdateHandler, rcvr)
	healthWrapped := wrapHandler(healthHandler, rcvr)
	stateWrapped := wrapHandler(stateHandler, rcvr)

	router.HandleFunc("/update", updateWrapped).Methods("POST")
	router.HandleFunc("/health", healthWrapped).Methods("GET")
	router.HandleFunc("/state", stateWrapped).Methods("GET")
	http.Handle("/", handlers.LoggingHandler(os.Stdout, router))

	err := http.ListenAndServe(listenStr, nil)
	if err != nil {
		log.Fatalf("Can't start http server: %s", err.Error())
	}
}

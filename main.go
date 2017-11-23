package main

import (
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime/pprof"
	"time"

	"github.com/Nitro/sidecar/catalog"
	"github.com/Nitro/sidecar/receiver"
	log "github.com/Sirupsen/logrus"
	"github.com/kelseyhightower/envconfig"
	"github.com/miekg/dns"
	"gopkg.in/relistan/rubberneck.v1"
)

var (
	profilerFile *os.File
)

type Config struct {
	BaseDomain      string `default:"sidecar.local." split_words:"true"`
	Compress        bool
	ForwardServers  []string      `split_words:"true"`
	UpstreamTimeout time.Duration `default:"3s" split_words:"true"`
	DnsPort         string        `default:"53" split_words:"true"`
	Ttl             uint32        `default:"60"`
	SidecarStateUrl string        `default:"http://localhost:7777/state.json" split_words:"true"`
	ProfileCpu      bool          `split_words:"true"`
	LoggingLevel    string        `split_words:"true" default:"info"`
}

func configureLoggingLevel(level string) {
	switch {
	case len(level) == 0:
		log.SetLevel(log.InfoLevel)
	case level == "info":
		log.SetLevel(log.InfoLevel)
	case level == "warn":
		log.SetLevel(log.WarnLevel)
	case level == "error":
		log.SetLevel(log.ErrorLevel)
	case level == "debug":
		log.SetLevel(log.DebugLevel)
	}
}

func startCpuProfiler() {
	log.Info("Starting CPU profiler")
	profilerFile, err := os.Create("sidecar-dns.cpu.prof")
	if err != nil {
		log.Fatalf("Can't write profiling file %s", err)
	}
	pprof.StartCPUProfile(profilerFile)
}

func startSignalHandler() {
	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt)
	go func() {
		for sig := range sigChannel {
			log.Printf("Captured %v, stopping profiler and exiting..", sig)
			pprof.StopCPUProfile()
			profilerFile.Close()
			os.Exit(0)
		}
	}()
}

func main() {
	var config Config
	var svcMap ServiceMap

	err := envconfig.Process("sdns", &config)
	if err != nil {
		log.Fatalf("Unable to process environment variables: %s", err)
	}

	configureLoggingLevel(config.LoggingLevel)

	if config.ProfileCpu {
		startSignalHandler()
		startCpuProfiler()
	}

	// Make sure we have a FQDN as the BaseDomain
	config.BaseDomain = dns.Fqdn(config.BaseDomain)

	// Set up the receiver
	rcvr := receiver.NewReceiver(RELOAD_BUFFER,
		func(state *catalog.ServicesState) {
			svcMap = state.ByService()
		}, // Store as the mapped structure for easy lookup
	)

	// Let's rubberneck that config
	rubberneck.
		NewPrinter(log.Infof, rubberneck.NoAddLineFeed).
		PrintWithLabel("sidecar-dns starting", &config)

	// Populate the initial state
	err = rcvr.FetchInitialState(config.SidecarStateUrl)
	if err != nil {
		log.Warnf("Unable to fetch Sidecar state on startup! Continuing... %s", err)
	}

	configureDnsServer(&config, svcMap)
	go serveDns(&config, "tcp")
	go serveDns(&config, "udp")

	// Watch for updates and manage the state
	go rcvr.ProcessUpdates()

	// Run the web API and block until it completes
	serveHttp("0.0.0.0", 7780, rcvr)
}

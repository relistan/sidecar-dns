package main

import (
	"fmt"
	"net"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Nitro/sidecar/catalog"
	"github.com/Nitro/sidecar/receiver"
	"github.com/Nitro/sidecar/service"
	log "github.com/Sirupsen/logrus"
	"github.com/kelseyhightower/envconfig"
	"github.com/miekg/dns"
	"gopkg.in/relistan/rubberneck.v1"
)

var (
	shuffleCounter int32 = 0
	udpClient      *dns.Client
	tcpClient      *dns.Client
	profilerFile   *os.File
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
}

type ServiceMap map[string][]*service.Service

// We wrap these up into a dns.HandlerFunc using makeHandler()
type wrappedHandlerFunc func(w dns.ResponseWriter, r *dns.Msg, config *Config, svcMap ServiceMap)

func makeHandler(handler wrappedHandlerFunc, config *Config, svcMap ServiceMap) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		handler(w, r, config, svcMap)
	}
}

func getServicesForQuery(r *dns.Msg, svcMap ServiceMap) []*service.Service {
	parts := strings.Split(r.Question[0].Name, ".")
	svcName := parts[0][1:] // Currently kind of cheating on parsing the query string

	var services []*service.Service

	if len(svcName) < 1 || len(svcMap[svcName]) < 1 {
		return services
	}

	for _, svc := range svcMap[svcName] {
		if svc.Status == service.ALIVE {
			services = append(services, svc)
		}
	}

	return services
}

func srvForService(svc *service.Service, config *Config) *dns.SRV {
	// No ports? Nothing to say. Unfortunately means we can't
	// serve SRV records for things in host networking mode.
	if len(svc.Ports) < 1 {
		return nil
	}

	return &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("_%s._%s.%s", svc.Name, "tcp", config.BaseDomain),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    config.Ttl,
		},
		Priority: 0,
		Weight:   10,
		Port:     uint16(svc.Ports[0].Port),
		Target:   fmt.Sprintf(
			"%s.%s.%s.addr.%s", svc.Name, svc.ID, svc.Hostname, config.BaseDomain,
		),
	}
}

func handleARecords(w dns.ResponseWriter, r *dns.Msg, config *Config, svcMap ServiceMap) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = config.Compress

	svcs := getServicesForQuery(r, svcMap)

	// Send empty reply
	if len(svcs) < 1 {
		w.WriteMsg(msg)
		return
	}

	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    config.Ttl,
		},
		Txt: []string{"Sidecar service " + svcs[0].Name},
	}

	switch r.Question[0].Qtype {
	case dns.TypeANY:
		fallthrough
	case dns.A:
		for _, svc := range svcs {
			msg.Answer = append(msg.Answer, srvForService(svc, config))
		}
		msg.Extra = append(msg.Extra, txt)

	w.WriteMsg(msg)
}

// DNS handler to serve records from Sidecar
func handleBaseDomain(w dns.ResponseWriter, r *dns.Msg, config *Config, svcMap ServiceMap) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = config.Compress

	svcs := getServicesForQuery(r, svcMap)

	// Send empty reply
	if len(svcs) < 1 {
		w.WriteMsg(msg)
		return
	}

	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    config.Ttl,
		},
		Txt: []string{"Sidecar service " + svcs[0].Name},
	}

	switch r.Question[0].Qtype {
	case dns.TypeANY:
		fallthrough
	case dns.TypeSRV:
		for _, svc := range svcs {
			msg.Answer = append(msg.Answer, srvForService(svc, config))
		}
		msg.Extra = append(msg.Extra, txt)
	case dns.TypeTXT:
		msg.Answer = append(msg.Answer, txt)
	}

	w.WriteMsg(msg)
}

// Round-robin the DNS servers. Uses an atomic increment operation.
func roundRobin(nameservers []string) string {
	index := atomic.AddInt32(&shuffleCounter, 1) % int32(len(nameservers))
	return nameservers[index]
}

// Retry decorator
func withRetries(delays []int, fn func() error) error {
	var err error
	for i := 0; i < len(delays); i++ {
		if err = fn(); err == nil {
			return nil
		}
		if i <= len(delays) {
			log.Debugf("Got error from query, retrying: %s", err)
			time.Sleep(time.Duration(delays[i]) * time.Millisecond)
		}
	}

	return err
}

// Forward records for domains that we don't host. This allows sidecar-dns to be
// the resolver for all records if needed.
func handleForward(w dns.ResponseWriter, r *dns.Msg, config *Config, _ ServiceMap) {
	client := udpClient

	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		client = tcpClient
	}

	var tried bool
	err := withRetries([]int{100, 300, 500, 1000}, func() error {
		upstream := roundRobin(config.ForwardServers)
		record, _, err := client.Exchange(r, upstream)

		if tried {
			log.Debugf("Retrying against %s", upstream)
		}
		tried = true

		// Success, write reply and return
		if err == nil {
			w.WriteMsg(record)
			return nil
		}

		return err
	})

	if err != nil {
		log.Errorf("Unable to forward request for %v: %s", r, err)
		failureMsg := new(dns.Msg)

		failureMsg.SetReply(r)
		failureMsg.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(failureMsg)
	}
}

func serveDns(config *Config, net string) {
	server := &dns.Server{
		Addr:       ":" + config.DnsPort,
		Net:        net,
		TsigSecret: nil,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to setup the "+net+" server: %s", err)
	}
}

// Set up the UDP and TCP clients we'll use for forward lookups
func prepareClients(config *Config) {
	udpClient = &dns.Client{
		Net:            "udp",
		Timeout:        config.UpstreamTimeout,
		SingleInflight: false,
	}

	tcpClient = &dns.Client{
		Net:            "udp",
		Timeout:        config.UpstreamTimeout,
		SingleInflight: false,
	}
}

// Make sure we have ports appended to nameservers. Default to 53.
func prepareNameservers(config *Config) {
	if len(config.ForwardServers) < 1 {
		log.Warn("No forwarding servers provided. Defaulting to server(s) from /etc/resolv.conf!")
		defaultCli, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			log.Fatalf("Unable to configure ANY forwarding servers: %s", err)
		}
		config.ForwardServers = defaultCli.Servers
	}

	servers := make([]string, len(config.ForwardServers))
	for i, svr := range config.ForwardServers {
		if strings.Contains(svr, ":") {
			servers[1] = svr
		} else {
			servers[i] = svr + ":53"
		}
	}

	config.ForwardServers = servers
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

	log.SetLevel(log.DebugLevel)

	if config.ProfileCpu {
		startSignalHandler()
		startCpuProfiler()
	}

	// Make sure we have a FQDN as the BaseDomain
	config.BaseDomain = dns.Fqdn(config.BaseDomain)

	// Set up the receiver
	rcvr := &receiver.Receiver{
		ReloadChan: make(chan time.Time, RELOAD_BUFFER),
		OnUpdate: func(state *catalog.ServicesState) {
			svcMap = state.ByService()
		}, // Store as the mapped structure for easy lookup
	}

	prepareNameservers(&config)
	prepareClients(&config)

	// Let's rubberneck that config
	rubberneck.
		NewPrinter(log.Infof, rubberneck.NoAddLineFeed).
		PrintWithLabel("sidecar-dns starting", &config)

	// Populate the initial state
	err = rcvr.FetchInitialState(config.SidecarStateUrl)
	if err != nil {
		log.Warnf("Unable to fetch Sidecar state on startup! Continuing... %s", err)
	}

	// Handle A records for names served in SRV records
	dns.HandleFunc("addr." + config.BaseDomain, makeHandler(handleARecords, &config, svcMap))

	// Handle the requested domain, serving SRV records from Sidecar
	dns.HandleFunc(config.BaseDomain, makeHandler(handleBaseDomain, &config, svcMap))

	// If we have ForwardServers, then we want to run the forward handler
	if len(config.ForwardServers) > 0 {
		dns.HandleFunc(".", makeHandler(handleForward, &config, svcMap))
	}

	go serveDns(&config, "tcp")
	go serveDns(&config, "udp")

	// Watch for updates and manage the state
	go rcvr.ProcessUpdates()

	// Run the web API and block until it completes
	serveHttp("0.0.0.0", 7780, rcvr)
}

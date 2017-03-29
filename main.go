package main

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Nitro/sidecar/catalog"
	"github.com/Nitro/sidecar/receiver"
	"github.com/Nitro/sidecar/service"
	log "github.com/Sirupsen/logrus"
	"github.com/kelseyhightower/envconfig"
	"github.com/miekg/dns"
	"github.com/relistan/rubberneck"
)

var (
	shuffleCounter int32 = 0
	udpClient      *dns.Client
	tcpClient      *dns.Client
)

type Config struct {
	BaseDomain      string `default:"sidecar.local." split_words:"true"`
	Compress        bool
	ForwardServers  []string      `split_words:"true"`
	UpstreamTimeout time.Duration `default:"3s" split_words:"true"`
	DnsPort         string        `default:"53" split_words:"true"`
	Ttl             uint32        `default:"60"`
	SidecarStateUrl string        `default:"http://localhost:7777/state.json"`
}

func makeHandler(handler func(w dns.ResponseWriter, r *dns.Msg, config *Config, rcvr *receiver.Receiver), config *Config, rcvr *receiver.Receiver) func(w dns.ResponseWriter, r *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		handler(w, r, config, rcvr)
	}
}

func getServicesForQuery(r *dns.Msg, state *catalog.ServicesState) []*service.Service {
	parts := strings.Split(r.Question[0].Name, ".")
	svcName := parts[0]

    var services []*service.Service
    state.EachService(func(hostname *string, id *string, svc *service.Service) {
        if svc.Name == name {
            services = append(services, svc)
        }
    })

	return services
}

func srvForService(svc *service.Service) *dns.SRV {
	return &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("_%s._%s.%s", svc.Name, "tcp", config.BaseDomain),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    config.Ttl,
		},
		Priority: 0,
		Weight:   10,
		Port:     51553,
		Target:   dns.Fqdn("some-host"), // Hostname
	}
}

// DNS handler to serve records from Sidecar
func handleSidecar(w dns.ResponseWriter, r *dns.Msg, config *Config, rcvr *receiver.Receiver) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = config.Compress

	svcs := getServicesForQuery(r, rcvr.CurrentState)

	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   config.BaseDomain,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    config.Ttl,
		},
		Txt: []string{"Sidecar service " + "foo"},
	}

	srv := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("_%s._%s.%s", "foo", "tcp", config.BaseDomain),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    config.Ttl,
		},
		Priority: 0,
		Weight:   10,
		Port:     51553,
		Target:   dns.Fqdn("some-host"), // Hostname
	}

	switch r.Question[0].Qtype {
	case dns.TypeANY:
		fallthrough
	case dns.TypeSRV:
		msg.Answer = append(msg.Answer, srv)
		msg.Extra = append(msg.Extra, txt)
	case dns.TypeTXT:
		msg.Answer = append(msg.Answer, txt)
		msg.Extra = append(msg.Extra, srv)
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
func handleForward(w dns.ResponseWriter, r *dns.Msg, config *Config, _ *receiver.Receiver) {
	client := udpClient

	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		client = tcpClient
	}

	err := withRetries([]int{100, 300, 500, 1000}, func() error {
		upstream := roundRobin(config.ForwardServers)
		record, _, err := client.Exchange(r, upstream)

		log.Debugf("Retrying against %s", upstream)

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
		SingleInflight: true,
	}

	tcpClient = &dns.Client{
		Net:            "udp",
		Timeout:        config.UpstreamTimeout,
		SingleInflight: true,
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

func main() {
	var config Config
	err := envconfig.Process("sdns", &config)
	if err != nil {
		log.Fatalf("Unable to process environment variables: %s", err)
	}

	// Make sure we have a FQDN as the BaseDomain
	config.BaseDomain = dns.Fqdn(config.BaseDomain)

	// Set up the receiver
	rcvr := &receiver.Receiver{
		ReloadChan: make(chan time.Time, RELOAD_BUFFER),
		OnUpdate:   func(state *catalog.ServicesState) {}, // Do nothing
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

	// Handle the requested domain, serving records from Sidecar
	dns.HandleFunc(config.BaseDomain, makeHandler(handleSidecar, &config, rcvr))

	// If we have ForwardServers, then we want to run the forward handler
	if len(config.ForwardServers) > 0 {
		dns.HandleFunc(".", makeHandler(handleForward, &config, rcvr))
	}

	go serveDns(&config, "tcp")
	go serveDns(&config, "udp")

	// Watch for updates and manage the state
	go rcvr.ProcessUpdates()

	// Run the web API and block until it completes
	serveHttp("0.0.0.0", 7780, rcvr)
}

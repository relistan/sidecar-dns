package main

import (
	"fmt"
	"net"
	_ "net/http/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Nitro/sidecar/service"
	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
)

var (
	shuffleCounter int32 = 0
	udpClient      *dns.Client
	tcpClient      *dns.Client
)

// Easier reference to a map of name => Service
type ServiceMap map[string][]*service.Service

// We wrap these up into a dns.HandlerFunc using makeHandler()
type wrappedHandlerFunc func(w dns.ResponseWriter, r *dns.Msg, config *Config, svcMap ServiceMap)

// configureDnsServer sets up the handlers for the DNS server
func configureDnsServer(config *Config, svcMap ServiceMap) {
	prepareNameservers(config)
	prepareClients(config)

	// Handle A records for names served in SRV records
	dns.HandleFunc("a."+config.BaseDomain, makeHandler(handleARecords, config, svcMap))

	// Handle the requested domain, serving SRV records from Sidecar
	dns.HandleFunc(config.BaseDomain, makeHandler(handleBaseDomain, config, svcMap))

	// If we have ForwardServers, then we want to run the forward handler
	if len(config.ForwardServers) > 0 {
		dns.HandleFunc(".", makeHandler(handleForward, config, svcMap))
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

// Set up the UDP and TCP clients we'll use for forward lookups
func prepareClients(config *Config) {
	udpClient = &dns.Client{
		Net:            "udp",
		Timeout:        config.UpstreamTimeout,
		SingleInflight: false,
	}

	tcpClient = &dns.Client{
		Net:            "tcp",
		Timeout:        config.UpstreamTimeout,
		SingleInflight: false,
	}
}

func makeHandler(handler wrappedHandlerFunc, config *Config, svcMap ServiceMap) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		handler(w, r, config, svcMap)
	}
}

func getIPsForQuery(query string, svcMap ServiceMap) []string {
	var addresses []string

	parts := strings.Split(query, ".")
	if len(parts) < 4 {
		log.Warnf("Got invalid addr query: '%s'", query)
		return addresses
	}

	// Query strings should be e.g.
	// 10109.tcp.nginx-raster.cc299047c106.a.sidecar.local

	portStr := parts[0]
	proto := parts[1]
	svcName := parts[2]
	svcID := parts[3]

	if len(svcName) < 1 || len(svcMap[svcName]) < 1 {
		return addresses
	}

	portInt, err := strconv.ParseInt(portStr, 10, 64)
	if err != nil {
		log.Errorf("Unable to parse port! Got '%s'", portStr)
		return addresses
	}

	for _, svc := range svcMap[svcName] {
		if svc.ID != svcID {
			continue
		}

		// No Alive check... we need to serve the IP if we know it

		for _, port := range svc.Ports {
			if port.Type == proto && port.ServicePort == portInt {
				addresses = append(addresses, port.IP)
			}
		}
	}

	return addresses
}

func getServicesForQuery(query string, svcMap ServiceMap) []*service.Service {
	parts := strings.Split(query, ".")
	svcName := parts[0][1:] // Currently kind of cheating on parsing the query string

	// Query strings should be e.g.
	// _10111._nginx-raster._tcp.sidecar.local

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

// srvForService returns a formatted SRV record for this Sidecar service
func srvForService(svc *service.Service, portStr string, config *Config) *dns.SRV {
	// No ports? Nothing to say. Unfortunately means we can't
	// serve SRV records for things in host networking mode.
	if len(svc.Ports) < 1 {
		return nil
	}

	port, err := strconv.ParseInt(portStr, 10, 64)
	if err != nil {
		return nil
	}

	var foundPort service.Port
	for _, p := range svc.Ports {
		if p.ServicePort == port {
			foundPort = p
			break
		}
	}

	if foundPort.Port == 0 {
		log.Warnf("Found port for %s but Port was nil", svc.Name)
		return nil
	}

	return &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("_%s._%s.%s", svc.Name, foundPort.Type, config.BaseDomain),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    config.Ttl,
		},
		Priority: 0,
		Weight:   10,
		Port:     uint16(foundPort.Port),
		Target: fmt.Sprintf(
			"%d.%s.%s.%s.a.%s", foundPort.ServicePort, foundPort.Type, svc.Name, svc.ID, config.BaseDomain,
		),
	}
}

// aForIP returns a formatted A record for this IP address
func aForIP(query, addr string, config *Config) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   query,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    config.Ttl,
		},
		A: net.ParseIP(addr),
	}
}

// DNS handler that responds to A record requests on our domain
func handleARecords(w dns.ResponseWriter, r *dns.Msg, config *Config, svcMap ServiceMap) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = config.Compress

	query := r.Question[0].Name
	addrs := getIPsForQuery(query, svcMap)

	// Send empty reply
	if len(addrs) < 1 {
		w.WriteMsg(msg)
		return
	}

	switch r.Question[0].Qtype {
	case dns.TypeA:
		for _, addr := range addrs {
			msg.Answer = append(msg.Answer, aForIP(query, addr, config))
			log.Debugf("Responding with A record... %#v", msg.Answer[len(msg.Answer)-1])
		}
	}
	w.WriteMsg(msg)
}

// DNS handler to serve records from Sidecar
func handleBaseDomain(w dns.ResponseWriter, r *dns.Msg, config *Config, svcMap ServiceMap) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = config.Compress

	parts := strings.Split(r.Question[0].Name, ".")
	if len(parts) < 2 {
		w.WriteMsg(msg)
		return
	}
	svcs := getServicesForQuery(strings.Join(parts[1:len(parts)-1], "."), svcMap)
	port := parts[0][1:]

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
		Txt: []string{"Sidecar service " + svcs[0].Name + " port " + port},
	}

	switch r.Question[0].Qtype {
	case dns.TypeANY:
		fallthrough
	case dns.TypeSRV:
		for _, svc := range svcs {
			srv := srvForService(svc, port, config)
			if srv != nil {
				msg.Answer = append(msg.Answer, srv)
			}
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

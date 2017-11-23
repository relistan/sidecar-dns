Sidecar-DNS
===========

This is a (working) work in progress to serve DNS SRV records and matching A
records from a Sidecar service discovery cluster. The service runs as a
companion to Sidecar, subscribing to Sidecar change events. It leverages the
miekg/dns package for very high performance DNS support.

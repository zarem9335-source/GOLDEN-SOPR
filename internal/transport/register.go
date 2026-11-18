// Package transport — registry for the GOLDEN SOPR classic + secure
// transports (Part A). New transports (grpc, hq, wg, wg-gaming, ss, dns,
// tls-camou, bond, naive, xhttp, reality) are registered by their own files.
package transport

func init() {
	// Classic (BackPack parity)
	Register(tcpFactory{mux: false})
	Register(tcpFactory{mux: true})
	Register(udpFactory{})
	Register(wsFactory{mux: false, tls: false})
	Register(wsFactory{mux: true, tls: false})
	Register(wsFactory{mux: false, tls: true})
	Register(wsFactory{mux: true, tls: true})
	// Secure (BackPack parity)
	Register(stealthFactory{})
	Register(pckFactory{})
	Register(kcpFactory{})
	Register(quicFactory{})
	Register(xdiFactory{})
}

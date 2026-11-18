// GOLDEN SOPR — registration of the new transports.
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// New transports (beyond BackPack's twelve):
//
//	grpc, hq, wg, wg-gaming (+ alias wggame), ss, dns, tls-camou, bond,
//	naive, xhttp, reality.
package transport

func init() {
	Register(&grpcFactory{})
	Register(&hqFactory{})
	Register(&wgFactory{name: "wg"})
	Register(&gamingFactory{name: "wg-gaming"})
	Register(&gamingFactory{name: "wggame"})
	Register(&ssFactory{})
	Register(&dnsFactory{})
	Register(&tlsCamouFactory{})
	Register(&bondFactory{})
	Register(&naiveFactory{name: "naive"})
	Register(&naiveFactory{name: "xhttp"})
	Register(&naiveFactory{name: "reality"})
}

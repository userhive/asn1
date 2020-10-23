package ldapclient

import (
	"log"
	"os"

	"github.com/userhive/asn1/ber"
)

// debugging type
//     - has a Printf method to write the debug output
type debugging bool

// Enable controls debugging mode.
func (debug *debugging) Enable(b bool) {
	*debug = debugging(b)
}

// Printf writes debug output.
func (debug debugging) Printf(format string, args ...interface{}) {
	if debug {
		log.Printf(format, args...)
	}
}

// PrintPacket dumps a packet.
func (debug debugging) PrintPacket(packet *ber.Packet) {
	if debug {
		packet.PrettyPrint(os.Stdout, 0)
	}
}

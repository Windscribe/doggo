package main

import (
	"fmt"
	"os"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

var (
	// Version and date of the build. This is injected at build-time.
	buildVersion = "unknown"
	buildDate    = "unknown"
	k            = koanf.New(".")
)

func main() {
	var (
		logger = initLogger()
	)

	// Initialize hub.
	hub := NewHub(logger, buildVersion)

	// Configure Flags
	// Use the POSIX compliant pflag lib instead of Go's flag lib.
	f := flag.NewFlagSet("config", flag.ContinueOnError)
	f.Usage = renderCustomHelp
	// Path to one or more config files to load into koanf along with some config params.
	f.StringSliceP("query", "q", []string{}, "Domain name to query")
	f.StringSliceP("type", "t", []string{}, "Type of DNS record to be queried (A, AAAA, MX etc)")
	f.StringSliceP("class", "c", []string{}, "Network class of the DNS record to be queried (IN, CH, HS etc)")
	f.StringSliceP("nameserver", "n", []string{}, "Address of the nameserver to send packets to")

	// Protocol Options
	f.BoolP("udp", "U", false, "Use the DNS protocol over UDP")
	f.BoolP("tcp", "T", false, "Use the DNS protocol over TCP")
	f.BoolP("doh", "H", false, "Use the DNS-over-HTTPS protocol")
	f.BoolP("dot", "S", false, "Use the DNS-over-TLS")

	// Resolver Options
	f.Int("timeout", 5, "Sets the timeout for a query to T seconds. The default timeout is 5 seconds.")
	f.Bool("search", false, "Use the search list provided in resolv.conf. It sets the `ndots` parameter as well unless overriden by `ndots` flag.")
	f.Int("ndots", 1, "Specify the ndots paramter. Default value is taken from resolv.conf and fallbacks to 1 if ndots statement is missing in resolv.conf")

	// Output Options
	f.BoolP("json", "J", false, "Set the output format as JSON")
	f.Bool("time", false, "Display how long it took for the response to arrive")
	f.Bool("color", true, "Show colored output")
	f.Bool("debug", false, "Enable debug mode")

	// Parse and Load Flags
	f.Parse(os.Args[1:])
	if err := k.Load(posflag.Provider(f, ".", k), nil); err != nil {
		hub.Logger.Errorf("error loading flags: %v", err)
		f.Usage()
		hub.Logger.Exit(2)
	}

	hub.FreeArgs = f.Args()

	// set log level
	if k.Bool("debug") {
		// Set logger level
		hub.Logger.SetLevel(logrus.DebugLevel)
	} else {
		hub.Logger.SetLevel(logrus.InfoLevel)
	}

	// Run the app.
	hub.Logger.Debug("Starting doggo 🐶")

	// Parse Query Args
	err := hub.loadQueryArgs()
	if err != nil {
		hub.Logger.WithError(err).Error("error parsing flags/arguments")
		hub.Logger.Exit(2)
	}

	// Load Nameservers
	for _, srv := range hub.QueryFlags.Nameservers {
		ns, err := initNameserver(srv)
		if err != nil {
			hub.Logger.WithError(err).Errorf("error parsing nameserver: %s", ns)
			hub.Logger.Exit(2)
		}
		if ns.Address != "" && ns.Type != "" {
			fmt.Println("appending", ns.Address, ns.Type)
			hub.Nameservers = append(hub.Nameservers, ns)
		}
	}

	// fallback to system nameserver
	if len(hub.Nameservers) == 0 {
		ns, err := getDefaultServers()
		if err != nil {
			hub.Logger.WithError(err).Errorf("error fetching system default nameserver")
			hub.Logger.Exit(2)
		}
		hub.Nameservers = ns
	}

	// Load Resolvers
	err = hub.initResolver()
	if err != nil {
		hub.Logger.WithError(err).Error("error loading resolver")
		hub.Logger.Exit(2)
	}
	// Start App
	if len(hub.QueryFlags.QNames) == 0 {
		f.Usage()
		hub.Logger.Exit(0)
	}
	err = hub.Lookup()
	if err != nil {
		hub.Logger.WithError(err).Error("error looking up DNS records")
		hub.Logger.Exit(2)
	}
}

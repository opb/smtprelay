package main

import (
	"flag"
	"os"
	"strings"
)

const (
	VERSION = "1.3.0"
)

var (
	versionInfo       = flag.Bool("version", false, "Show version information")
)

var config = map[string]string{}

func ConfigLoad() {
	flag.Parse()

	config = map[string]string{
		"RELAY_HOSTNAME": "localhost.localdomain",
		"RELAY_LISTEN": "127.0.0.1:2525", // tls://127.0.0.1:465,starttls://127.0.0.1:587 (multiple, comma separated)
		"RELAY_ALLOWED_NETS": "127.0.0.1/32", // comma separated CIDR ranges for email sources
		"RELAY_ALLOWED_RECIPIENTS": "", // comma separated domains for valid destinations
		"RELAY_REMOTE_HOST": "", // IP:Port
		"RELAY_REMOTE_USER": "",
		"RELAY_REMOTE_PASS": "",
		"RELAY_FORCE_TLS": "0",
		"RELAY_CERT_FILE": "smtpd.pem", // X509 file
		"RELAY_KEY_FILE": "smtpd.key", // X509 file
	}

	boolOptions := []string{"RELAY_FORCE_TLS"}

	for k := range config{
		if  t := os.Getenv(k); t != ""{
			config[k] = t
		}
	}

	for _, o := range boolOptions{
		config[o] = boolString(config[o])
	}
}

func boolString(input string) string{
	valid := []string{"y", "yes", "true", "1"}
	i := strings.ToLower(input)
	for _, v := range valid{
		if i == v{
			return "1"
		}
	}

	return "0"
}

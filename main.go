package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"

	"github.com/chrj/smtpd"
	"github.com/vharitonsky/iniflags"
)

var (
	hostName   = flag.String("hostname", "localhost.localdomain", "Server hostname")
	welcomeMsg = flag.String("welcome_msg", "", "Welcome message for SMTP session")
	listen     = flag.String("listen", "127.0.0.1:25 [::1]:25", "Address and port to listen for incoming SMTP")
	localCert  = flag.String("local_cert", "", "SSL certificate for STARTTLS/TLS")
	localKey   = flag.String("local_key", "", "SSL private key for STARTTLS/TLS")
	localForceTLS = flag.Bool("local_forcetls", false, "Force STARTTLS (needs local_cert and local_key)")
	remoteHost = flag.String("remote_host", "smtp.gmail.com", "Outgoing SMTP server")
	remotePort = flag.Int("remote_port", 587, "Outgoing SMTP port")
	remoteUser = flag.String("remote_user", "", "Username for authentication on outgoing SMTP server")
	remotePass = flag.String("remote_pass", "", "Password for authentication on outgoing SMTP server")
)

func handler(peer smtpd.Peer, env smtpd.Envelope) error {

	return smtp.SendMail(
		fmt.Sprintf("%s:%d", *remoteHost, *remotePort),
		smtp.PlainAuth("", *remoteUser, *remotePass, *remoteHost),
		env.Sender,
		env.Recipients,
		env.Data,
	)
}

func main() {

	iniflags.Parse()

	server := &smtpd.Server{
		Hostname:	*hostName,
		WelcomeMessage: *welcomeMsg,
		Handler:        handler,
		ForceTLS:	*localForceTLS,
	}

	listeners := strings.Split(*listen, " ")

	for i := range(listeners) {
		listener := listeners[i]

		if strings.Index(listeners[i], "://") == -1 {
			;
		} else if strings.HasPrefix(listeners[i], "tls://") || strings.HasPrefix(listeners[i], "starttls://") {

			listener = strings.TrimPrefix(listener, "tls://")
			listener = strings.TrimPrefix(listener, "starttls://")

			if *localCert == "" || *localKey == "" {
				log.Fatal("TLS certificate/key not defined in config")
			}

			cert, err := tls.LoadX509KeyPair(*localCert, *localKey)
			if err != nil {
				log.Fatal(err)
			}

			server.TLSConfig = &tls.Config {
				Certificates: [] tls.Certificate{cert},
			}
		} else {
			log.Fatal("Unknown protocol in listener ", listener)
		}

		log.Printf("Listen on %s ...\n", listener)
		go server.ListenAndServe(listener)
	}

	for true {
		time.Sleep(time.Minute)
	}
}
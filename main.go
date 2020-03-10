package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/chrj/smtpd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var (
	mailsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtprelay_processed_emails_total",
		Help: "The total number of processed emails, successfully or not",
	})
	mailsSuccesses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtprelay_processed_emails_success",
		Help: "The number of successfully processed emails",
	})
	mailsFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtprelay_processed_emails_fail",
		Help: "The number of unsuccessfully processed emails",
	})
)

func connectionChecker(peer smtpd.Peer) error {
	var peerIP net.IP
	if addr, ok := peer.Addr.(*net.TCPAddr); ok {
		peerIP = net.ParseIP(addr.IP.String())
	} else {
		return smtpd.Error{Code: 421, Message: "Denied"}
	}

	nets := strings.Split(config["RELAY_ALLOWED_NETS"], ",")

	for i := range nets {
		_, allowedNet, _ := net.ParseCIDR(nets[i])

		if allowedNet.Contains(peerIP) {
			return nil
		}
	}

	return smtpd.Error{Code: 421, Message: "Denied"}
}

func recipientChecker(peer smtpd.Peer, addr string) error {
	if config["RELAY_ALLOWED_RECIPIENTS"] == "" {
		return nil
	}

	split := strings.Split(addr, "@")
	destDomain := split[len(split) - 1]

	for _, valid := range strings.Split(config["RELAY_ALLOWED_RECIPIENTS"], ","){
		if destDomain == valid{
			return nil
		}
	}

	return smtpd.Error{Code: 451, Message: "Bad recipient address"}
}



func mailHandler(peer smtpd.Peer, env smtpd.Envelope) error {
	peerIP := ""
	if addr, ok := peer.Addr.(*net.TCPAddr); ok {
		peerIP = addr.IP.String()
	}

	log.Printf("new mail from=<%s> to=%s peer=[%s]\n", env.Sender,
		env.Recipients, peerIP)

	var auth smtp.Auth
	host, _, _ := net.SplitHostPort(config["RELAY_REMOTE_HOST"])

	if config["RELAY_REMOTE_USER"] != "" && config["RELAY_REMOTE_PASS"] != "" {
		auth = smtp.PlainAuth("", config["RELAY_REMOTE_USER"], config["RELAY_REMOTE_PASS"], host)
	}

	env.AddReceivedLine(peer)

	log.Printf("delivering using smarthost %s\n", config["RELAY_REMOTE_HOST"])

	sender := env.Sender

	err := SendMail(
		config["RELAY_REMOTE_HOST"],
		auth,
		sender,
		env.Recipients,
		env.Data,
	)
	if err != nil {
		log.Printf("delivery failed: %v\n", err)
		mailsFailures.Inc()
		mailsProcessed.Inc()
		return smtpd.Error{Code: 554, Message: "Forwarding failed"}
	}

	log.Printf("%s delivery successful\n", env.Recipients)
	mailsSuccesses.Inc()
	mailsProcessed.Inc()

	return nil
}

func main() {

	ConfigLoad()

	if *versionInfo {
		fmt.Printf("smtprelay/%s\n", VERSION)
		os.Exit(0)
	}

	listeners := strings.Split(config["RELAY_LISTEN"], ",")

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	http.Handle("/metrics", promhttp.Handler())
	srv := http.Server{Addr: ":2112", Handler: http.DefaultServeMux}

	go func(){
		err := srv.ListenAndServe()
		if err != nil {
			log.Println(err)
		}
	}()

	for i := range listeners {
		listener := listeners[i]

		server := &smtpd.Server{
			Hostname:          config["RELAY_HOSTNAME"],
			WelcomeMessage:    config["RELAY_HOSTNAME"] + " ESMTP Ready",
			ConnectionChecker: connectionChecker,
			RecipientChecker:  recipientChecker,
			Handler:           mailHandler,
		}

		if strings.Index(listeners[i], "://") == -1 {
			log.Printf("Listen on %s ...\n", listener)
			go server.ListenAndServe(listener)
		} else if strings.HasPrefix(listeners[i], "starttls://") {
			listener = strings.TrimPrefix(listener, "starttls://")

			if config["RELAY_CERT_FILE"] == "" || config["RELAY_KEY_FILE"] == "" {
				log.Fatal("TLS certificate/key not defined in config")
			}

			cert, err := tls.LoadX509KeyPair(config["RELAY_CERT_FILE"], config["RELAY_KEY_FILE"])
			if err != nil {
				log.Fatal(err)
			}

			server.TLSConfig = &tls.Config{
				PreferServerCipherSuites: true,
				MinVersion:               tls.VersionTLS11,

				// Ciphersuites as defined in stock Go but without 3DES
				// https://golang.org/src/crypto/tls/cipher_suites.go
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // does not provide PFS
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384, // does not provide PFS
					tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				Certificates: []tls.Certificate{cert},
			}
			server.ForceTLS = config["RELAY_FORCE_TLS"] == "1"

			log.Printf("Listen on %s (STARTSSL) ...\n", listener)
			lsnr, err := net.Listen("tcp", listener)
			if err != nil {
				log.Fatal(err)
			}
			defer lsnr.Close()

			go server.Serve(lsnr)
		} else if strings.HasPrefix(listeners[i], "tls://") {

			listener = strings.TrimPrefix(listener, "tls://")

			if config["RELAY_CERT_FILE"] == "" || config["RELAY_KEY_FILE"] == "" {
				log.Fatal("TLS certificate/key not defined in config")
			}

			cert, err := tls.LoadX509KeyPair(config["RELAY_CERT_FILE"], config["RELAY_KEY_FILE"])
			if err != nil {
				log.Fatal(err)
			}

			server.TLSConfig = &tls.Config{
				PreferServerCipherSuites: true,
				MinVersion:               tls.VersionTLS11,

				// Ciphersuites as defined in stock Go but without 3DES and RC4
				// https://golang.org/src/crypto/tls/cipher_suites.go
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // does not provide PFS
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384, // does not provide PFS
					tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				Certificates: []tls.Certificate{cert},
			}

			log.Printf("Listen on %s (TLS) ...\n", listener)
			lsnr, err := tls.Listen("tcp", listener, server.TLSConfig)
			if err != nil {
				log.Fatal(err)
			}
			defer lsnr.Close()

			go server.Serve(lsnr)
		} else {
			log.Fatal("Unknown protocol in listener ", listener)
		}
	}

	<-signalChan
	fmt.Println("Shutting down server...")
	err := srv.Shutdown(context.Background())
	if err != nil {
		log.Println(err)
	}

}

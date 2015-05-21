package main

import (
	"crypto/tls"
	_ "expvar"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/garyburd/redigo/redis"
)

var (
	debugFlag  = flag.Bool("debug", false, "Run server in debug mode?")
	configFlag = flag.String("config", "charon.json", "Configuration file to use")
)

func main() {
	flag.Parse()

	e1, err := net.Listen("tcp", "0.0.0.0:8123")
	if err != nil {
		logger.Printf("Error starting http server")
	} else {
		logger.Printf("Http Server Started on port 8123")
		go http.Serve(e1, nil)
	}

	SetupNumerics()
	SetupConfig(*configFlag)
	SetupPool()
	var listeners []net.Listener
	// Listen for incoming connections.
	var tconfig tls.Config
	var cert tls.Certificate
	var tlser error
	if len(config.TLSPorts) > 0 {
		cert, tlser = tls.LoadX509KeyPair(config.TLSCertPath, config.TLSKeyPath)
		if tlser == nil {
			tconfig = tls.Config{Certificates: []tls.Certificate{cert}}
		} else {
			logger.Printf("TLS ERR: %s", tlser.Error())
		}
	}
	for _, LISTENING_IP := range config.ListenIPs {
		for _, LISTENING_PORT := range config.ListenPorts {
			l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", LISTENING_IP, LISTENING_PORT))
			if err != nil {
				logger.Printf("Error listening: " + err.Error())
				os.Exit(1)
			} else {
				listeners = append(listeners, l)
				logger.Printf("Listening on %s:%d", LISTENING_IP, LISTENING_PORT)
			}
		}
		if tlser == nil {
			for _, LISTENING_PORT := range config.TLSPorts {
				l, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", LISTENING_IP, LISTENING_PORT), &tconfig)
				if err != nil {
					logger.Printf("Error listening: " + err.Error())
					os.Exit(1)
				} else {
					listeners = append(listeners, l)
					logger.Printf("TLS Listening on %s:%d", LISTENING_IP, LISTENING_PORT)
				}
			}
		}
	}

	// Close the listener when the application closes.
	for _, l := range listeners {
		defer l.Close()
	}

	for _, l := range listeners {
		go listenerthing(l)
	}

	periodicStatusUpdate()
}

func listenerthing(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Printf("Error accepting: " + err.Error())
		} else {
			user := NewUser()
			user.SetConn(conn)
			checkMaxUsers()
			go user.HandleRequests()
		}
	}
}

func checkMaxUsers() {
	if len(userlist) > maxUsers {
		maxUsers = len(userlist)
	}
}

func periodicStatusUpdate() {
	for {
		if *debugFlag {
			logger.Printf("Status: %d current Goroutines", runtime.NumGoroutine())
			logger.Printf("Status: %d current users", len(userlist))
			logger.Printf("Status: %d current channels", len(chanlist))
		}
		time.Sleep(config.StatTime * time.Second)
	}
}

func SetupPool() {
	RedisPool = &redis.Pool{
		MaxIdle: 10,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", fmt.Sprintf("%s:%d", config.RedisHost, config.RedisPort))
			if err != nil {
				return nil, err
			}

			if config.RedisPassword != "" {
				if _, err := c.Do("AUTH", config.RedisPassword); err != nil {
					c.Close()
					return nil, err
				}
			}
			return c, nil
		},
	}
}

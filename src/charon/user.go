package main

import (
	"bufio"
	"fmt"
	"irc/message"
	debuglogger "log"
	"net"
	"strings"
	"time"
)

type User struct {
	nick       string
	user       string
	ident      string
	dead       bool
	nickset    bool
	waiting    bool
	connection net.Conn
	id         int
	realname   string
	userset    bool
	registered bool
	ip         string
	realip     string
	host       string
	realhost   string
	epoch      time.Time
	lastrcv    time.Time
	nextcheck  time.Time
	chanlist   map[string]*Channel
	oper       bool
	system     bool
	ConnType   string
	resolved   chan bool
}

func (user *User) PingChecker() {
	for {
		if user.dead {
			return
		}
		if time.Now().After(user.nextcheck) {
			if user.waiting {
				since := time.Since(user.lastrcv).Seconds()
				user.Quit(fmt.Sprintf("Ping Timeout: %.0f seconds", since))
				return
			} else {
				user.SendLine(fmt.Sprintf("PING :%s", config.ServerName))
				user.waiting = true
				user.nextcheck.Add(config.PingTime * time.Second)
				logger.Printf("Sent user %s ping", user.nick)
			}
		}
		time.Sleep(config.PingCheckTime * time.Second)
	}
}

func (user *User) FireNumeric(numeric int, args ...interface{}) {
	msg := fmt.Sprintf(":%s %.3d %s ", config.ServerName, numeric, user.nick) + fmt.Sprintf(NUM[numeric], args...)
	user.SendLine(msg)
}

func NewUser() *User {
	counter = counter + 1

	//TODO: &-invocate this better
	user := &User{id: counter, nick: "*"}
	user.chanlist = make(map[string]*Channel)
	user.epoch = time.Now()
	user.lastrcv = time.Now()
	user.nextcheck = time.Now().Add(config.PingTime * time.Second)
	userlist[user.id] = user
	user.resolved = make(chan bool)
	return user
}

func (user *User) SetConn(conn net.Conn) {
	//TODO: Make this attachable
	user.connection = conn
	SetUserIPInfo(user)
	logger.Printf("New connection from " + user.realip)
	user.realhost = user.realip
	if !config.Cloaking {
		user.host = user.realip
	} else {
		if user.ConnType == "IP4" {
			k := CloakIP4(user.realip)
			user.host = k
			user.ip = k
		} else {
			k := CloakIP6(user.realip)
			user.host = k
			user.ip = k
		}
	}
	if config.ResolveHosts {
		go user.UserHostLookup()
	}
	go user.PingChecker()
}

func (user *User) SendLine(msg string) {
	msg = fmt.Sprintf("%s\n", msg)

	if user.dead || user.system {
		return
	}

	_, err := user.connection.Write([]byte(msg))

	if err != nil {
		user.dead = true
		user.Quit("Error")
		logger.Printf("Error sending message to %s, disconnecting\n", user.nick)
		return
	}

	if *debugFlag {
		debuglogger.Printf("Send to %s: %s", user.nick, msg)
	}
}

func (user *User) SendLinef(msg string, args ...interface{}) {
	user.SendLine(fmt.Sprintf(msg, args...))
}

func (user *User) HandleRequests() {
	b := bufio.NewReader(user.connection)

	for {
		if user.dead {
			return
		}

		line, err := b.ReadString('\n')

		if err != nil {
			logger.Printf("Error reading: " + err.Error())
			user.dead = true
			user.Quit("Error")
			return
		}

		if line == "" {
			user.dead = true
			user.Quit("Error")
			return
		}

		line = strings.TrimSpace(line)

		if *debugFlag {
			debuglogger.Println("Receive from", fmt.Sprintf("%s:", user.nick), line)
		}

		//TODO: send this via a channel to a main thread for sync issues
		ProcessLine(user, line)
	}
}

func (user *User) UserRegistrationFinished() {
	<-user.resolved // Wait for DNS resolution

	user.registered = true
	logger.Printf("User %d finished registration", user.id)
	user.FireNumeric(RPL_WELCOME, user.nick, user.ident, user.host)
	user.FireNumeric(RPL_YOURHOST, config.ServerName, software, softwarev)
	user.FireNumeric(RPL_CREATED, epoch)

	//TODO fire RPL_MYINFO when we actually have enough stuff to do it
	user.FireNumeric(RPL_ISUPPORT, isupport)

	// Show user their hidden host if applicable
	if user.host != user.realhost {
		user.FireNumeric(RPL_HOSTHIDDEN, user.host)
	}

	if *debugFlag {
		user.SendLinef(":%s NOTICE %s :This server is in debug mode. Someone is attached to the console reading debug output. Tread with care.", config.ServerName, user.nick)
	}

	if !config.Privacy {
		user.SendLinef(":%s NOTICE %s :This server has privacy protections disabled.", config.ServerName, user.nick)
	}

	LusersHandler(user, nil)

	for _, k := range config.AutoJoin {
		JoinHandler(user, &message.Message{Args: []string{"JOIN", k}})
	}
}

func (user *User) UserHostLookup() {
	// wait for the reverse DNS lookup to finish
	defer func() {
		user.resolved <- true
	}()

	user.SendLinef(":%s NOTICE %s :*** Looking up your hostname...", config.ServerName, user.nick)

	adds, err := net.LookupAddr(user.realip)

	if err != nil {
		user.SendLinef("%s NOTICE %s :*** Unable to resolve your hostname", config.ServerName, user.nick)
		return
	}

	addstring := adds[0]
	adds, err = net.LookupHost(addstring)

	if err != nil {
		user.SendLinef("%s NOTICE %s :*** Unable to resolve your hostname", config.ServerName, user.nick)
		return
	}

	for _, k := range adds {
		if user.realip == k {
			addstring = strings.TrimSuffix(addstring, ".")
			user.realhost = addstring

			if config.Cloaking {
				user.host = CloakHost(addstring)
			} else {
				user.host = addstring
			}

			user.SendLinef(":%s NOTICE %s :*** Found your hostname", config.ServerName, user.nick)

			return
		}
	}

	user.SendLinef(":%s NOTICE %s :*** Your forward and reverse DNS do not match, ignoring hostname", config.ServerName, user.nick)
}

func (user *User) GetHostMask() string {
	return fmt.Sprintf("%s!%s@%s", user.nick, user.ident, user.host)
}

func (user *User) IsIn(channel *Channel) bool {
	for _, k := range user.chanlist {
		if k == channel {
			return true
		}
	}
	return false
}

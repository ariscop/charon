//process lines
package main

import (
	"irc/message"
	"log"
	"time"
)

type Handler func(*User, *message.Message)

var Handlers map[string]Handler

func NullHandler(u *User, m *message.Message) {}

func init() {
	Handlers = map[string]Handler{
		"QUIT":     QuitCommandHandler,
		"NICK":     NickHandler,
		"USER":     UserHandler,
		"JOIN":     JoinHandler,
		"PRIVMSG":  PrivmsgHandler,
		"PONG":     NullHandler, // TODO: Implement
		"LUSERS":   LusersHandler,
		"PART":     PartHandler,
		"TOPIC":    TopicHandler,
		"CAP":      NullHandler, // TODO: Implement
		"MODE":     ModeHandler,
		"PING":     PingHandler,
		"WHO":      WhoHandler,
		"KICK":     KickHandler,
		"LIST":     ListHandler,
		"NAMES":    NamesHandler,
		"OPER":     OperHandler,
		"REHASH":   RehashHandler,
		"SHUTDOWN": ShutdownHandler,
		"KILL":     KillHandler,
		"WHOIS":    WhoisHandler,
	}
}

//takes a line and a user and processes it.
func ProcessLine(user *User, msg string) {
	user.lastrcv = time.Now()
	user.nextcheck = time.Now().Add(config.PingTime * time.Second)
	user.waiting = false

	mymsg := message.ParseMessage(msg)

	handler, ok := Handlers[mymsg.Verb]
	log.Printf("Handler %#v: %v", handler, ok)
	if ok {
		switch mymsg.Verb {
		case "CAP", "NICK", "USER", "QUIT", "PONG", "PING":
			log.Printf("Running raw handler for %s", mymsg.Verb)
			handler(user, mymsg)

		default:
			log.Printf("Running protected handler for %s", mymsg.Verb)
			FireIfRegistered(handler, user, mymsg)
		}
	} else {
		CommandNotFound(user, mymsg)
	}
}

func FireIfRegistered(handler Handler, user *User, line *message.Message) {
	if user.registered {
		handler(user, line)
	} else {
		user.FireNumeric(ERR_NOTREGISTERED)
	}
}

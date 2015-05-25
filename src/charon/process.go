//process lines
package main

import (
	"irc/message"
	"log"
	"time"
)

type Handler func(*User, []string)

var Handlers map[string]Handler

func NullHandler(u *User, s []string) {}

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

	//XXX HACK: make things work for now
	//TODO: remove this
	mymsg.Args = append([]string{mymsg.Verb}, mymsg.Args...)

	log.Printf("%s: %#v", msg, mymsg)

	handler, ok := Handlers[mymsg.Verb]
	log.Printf("Handler %#v: %v", handler, ok)
	if ok {
		switch mymsg.Verb {
		case "CAP", "NICK", "USER", "QUIT", "PONG", "PING":
			log.Printf("Running raw handler for %s", mymsg.Verb)
			handler(user, mymsg.Args)

		default:
			log.Printf("Running protected handler for %s", mymsg.Verb)
			FireIfRegistered(handler, user, mymsg.Args)
		}
	} else {
		CommandNotFound(user, mymsg.Args)
	}
}

func FireIfRegistered(handler Handler, user *User, args []string) {
	if user.registered {
		handler(user, args)
	} else {
		user.FireNumeric(ERR_NOTREGISTERED)
	}
}

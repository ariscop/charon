package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

type User struct {
	nick       string
	user       string
	ident      string
	ip         string
	dead       bool
	connection net.Conn
	id         int
}

func (user *User) Quit() {
	user.dead = true
	if user.connection != nil {
		user.connection.Close()
	}
	delete(userlist, user.id)
}

func (user *User) SendLine(msg string) {
	msg = fmt.Sprintf("%s\n", msg)
	user.connection.Write([]byte(msg))
}

func (user *User) HandleRequests() {
	b := bufio.NewReader(user.connection)
	for {
		if user.dead {
			break
		}
		line, err := b.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading:", err.Error())
			user.Quit()
		}
		line = strings.TrimSpace(line)
		fmt.Println("Received Line: ", line)
		// Send a response back to person contacting us.
		go ProcessLine(user, line)
	}
}
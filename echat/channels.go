package main

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"time"
)

//Channel...
//represents an irc channel
type Channel struct {
	name      string
	epoch     time.Time
	userlist  map[int]*User
	usermodes map[*User]string
	cmodes    string
	topic     string
	topichost string
	topictime int64
}

func (channel *Channel) SetTopic(newtopic string, hostmask string) {
	channel.topic = newtopic
	channel.topichost = hostmask
	channel.topictime = time.Now().Unix()
	channel.SendLinef(":%s TOPIC %s :%s", hostmask, channel.name, newtopic)
}

func NewChannel(newname string) *Channel {
	chann := &Channel{name: newname, epoch: time.Now()}
	chann.userlist = make(map[int]*User)
	chann.usermodes = make(map[*User]string)
	chanlist[strings.ToLower(chann.name)] = chann
	chann.cmodes = default_cmode
	log.Printf("Channel %s created\n", chann.name)
	return chann
}

func (channel *Channel) JoinUser(user *User) {
	channel.userlist[user.id] = user
	if len(channel.userlist) == 1 {
		channel.usermodes[user] = "o"
	}
	channel.SendLinef(":%s JOIN %s", user.GetHostMask(), channel.name)
	if len(channel.topic) > 0 {
		channel.FireTopic(user)
	}
	channel.FireNames(user)
}

func (channel *Channel) GetUserPrefix(user *User) string {
	if strings.Contains(channel.usermodes[user], "o") {
		return "@"
	}
	return ""
}

func (channel *Channel) FireTopic(user *User) {
	if len(channel.topic) > 0 {
		user.FireNumeric(RPL_TOPIC, channel.name, channel.topic)
		user.FireNumeric(RPL_TOPICWHOTIME, channel.name, channel.topichost, channel.topictime)
	} else {
		user.FireNumeric(RPL_NOTOPIC, channel.name)
	}
}

func (channel *Channel) FireNames(user *User) {
	var buffer bytes.Buffer
	for _, k := range userlist {
		if buffer.Len()+len(channel.GetUserPrefix(k))+len(user.nick) > 500 {
			user.FireNumeric(RPL_NAMEPLY, channel.name, strings.TrimSpace(buffer.String()))
			buffer.Reset()
		}
		buffer.WriteString(channel.GetUserPrefix(k))
		buffer.WriteString(k.nick)
		buffer.WriteString(" ")
	}
	if buffer.Len() > 1 {
		resp := strings.TrimSpace(buffer.String())
		user.FireNumeric(RPL_NAMEPLY, channel.name, resp)
	}
	user.FireNumeric(RPL_ENDOFNAMES, channel.name)
}

func (channel *Channel) GetUserList() []*User {
	list := []*User{}
	for _, k := range channel.userlist {
		list = append(list, k)
	}
	return list
}

func (channel *Channel) GetUserPriv(user *User) int {
	score := 0
	if strings.Contains(channel.usermodes[user], "o") {
		score += 100
	}
	return score
}

func (channel *Channel) ShouldIDie() {
	if len(channel.userlist) < 1 {
		delete(chanlist, strings.ToLower(channel.name))
		log.Printf("Channel %s has no users, destroying\n", channel.name)
	}
}

func (channel *Channel) FireModes(user *User) {
	user.FireNumeric(RPL_CHANNELMODEIS, channel.name, channel.cmodes)
	user.FireNumeric(RPL_CREATIONTIME, channel.name, channel.epoch.Unix())
}

func (channel *Channel) HasMode(mode string) bool {
	if strings.Contains(channel.cmodes, mode) {
		return true
	} else {
		return false
	}
}

func (channel *Channel) OP(user *User, changing *User) {
	if !strings.Contains(channel.usermodes[user], "o") {
		channel.usermodes[user] = strcat(channel.usermodes[user], "o")
		channel.SendLinef(":%s MODE %s +o %s", changing.GetHostMask(), channel.name, user.nick)
	}
}

func (channel *Channel) DEOP(user *User, changing *User) {
	if strings.Contains(channel.usermodes[user], "o") {
		channel.usermodes[user] = strings.Replace(channel.usermodes[user], "o", "", 1)
		channel.SendLinef(":%s MODE %s -o %s", changing.GetHostMask(), channel.name, user.nick)
	}
}

func (channel *Channel) SetMode(mode string, changing *User) {
	if !strings.Contains(channel.cmodes, mode) {
		channel.cmodes = strcat(channel.cmodes, mode)
		channel.SendLinef(":%s MODE %s +%s", changing.GetHostMask(), channel.name, mode)
	}
}

func (channel *Channel) UnsetMode(mode string, changing *User) {
	if strings.Contains(channel.cmodes, mode) {
		channel.cmodes = strings.Replace(channel.cmodes, mode, "", 1)
		channel.SendLinef(":%s MODE %s -%s", changing.GetHostMask(), channel.name, mode)
	}
}

func (channel *Channel) HasUser(user *User) bool {
	if channel.userlist[user.id] == user {
		return true
	} else {
		return false
	}
}

func (channel *Channel) SendLinef(msg string, args ...interface{}) {
	for _, k := range channel.userlist {
		k.SendLine(fmt.Sprintf(msg, args...))
	}
}

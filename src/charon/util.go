package main

import (
	"irc/message"
	"strings"
)

func GetUserByNick(nick string) *User {
	nick = strings.ToLower(nick)
	if nick == strings.ToLower(SystemUser.nick) {
		return SystemUser
	}
	for _, k := range userlist {
		if strings.ToLower(k.nick) == nick {
			return k
		}
	}
	return nil
}

func SetUserIPInfo(user *User) {
	ip := user.connection.RemoteAddr().String()
	if !strings.HasPrefix(ip, "[") {
		//ipv4
		user.ConnType = "IP4"
		user.realip = strings.Split(ip, ":")[0]
	} else {
		user.ConnType = "IP6"
		ip = strings.Split(ip, "]")[0]
		ip = strings.TrimPrefix(ip, "[")
		user.realip = ip
	}
}

func GetChannelByName(name string) *Channel {
	return chanlist[strings.ToLower(name)]
}

func SendToMany(msg string, list []*User) {
	users := make(map[*User]int)
	for _, j := range list {
		users[j] = 0
	}
	for j, _ := range users {
		j.SendLine(msg)
	}
}

func ValidChanName(name string) bool {
	if ChanHasBadChars(name) {
		return false
	}
	for _, k := range valid_chan_prefix {
		if strings.HasPrefix(name, k) {
			return true
		}
	}
	return false
}

func NickHasBadChars(nick string) bool {
	for _, k := range global_bad_chars {
		if strings.Contains(nick, k) {
			return true
		}
	}
	for _, k := range valid_chan_prefix {
		if strings.Contains(nick, k) {
			return true
		}
	}
	return false
}

func ChanHasBadChars(nick string) bool {
	for _, k := range global_bad_chars {
		if strings.Contains(nick, k) {
			return true
		}
	}
	return false
}

func ChanUserNone(name string) int {
	if GetChannelByName(name) != nil {
		return 1
	} else if GetUserByNick(name) != nil {
		return 2
	} else {
		return 0
	}
}

func WildcardMatch(text string, pattern string) bool {
	cards := strings.Split(pattern, "*")
	for _, card := range cards {
		index := strings.Index(text, card)
		if index == -1 {
			return false
		}
		text = text[index+len(card):]
	}
	return true
}

func SetupSystemUser() {
	for _, k := range config.LogChannels {
		ModeHandler(SystemUser, &message.Message{Args: []string{k, "+A"}})
	}
	if !config.SystemJoinChannels {
		for _, k := range SystemUser.chanlist {
			if !k.IsLogChan() {
				PartHandler(SystemUser, &message.Message{Args: []string{"PART", k.name}})
			}
		}
	}
}

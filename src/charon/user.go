package main

import (
	"bufio"
	"bytes"
	"fmt"
	"irc/message"
	debuglogger "log"
	"net"
	"os"
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

func QuitCommandHandler(user *User, line *message.Message) {
	var reason string
	if len(line.Args) > 0 {
		reason = line.Args[0]
	} else {
		reason = config.DefaultQuitReason
	}

	user.Quit(reason)

	if user.oper {
		opercount--
	}

	logger.Printf("User %s Quit (%s)", user.nick, reason)
}

func (user *User) Quit(reason string) {
	targets := []*User{user}

	for _, k := range user.chanlist {
		targets = append(targets, k.GetUserList()...)
		delete(k.userlist, user.id)
		delete(user.chanlist, k.name)
		delete(k.usermodes, user)
		k.ShouldIDie()
	}

	SendToMany(fmt.Sprintf(":%s QUIT :%s", user.GetHostMask(), reason), targets)
	user.SendLinef("ERROR :Closing Link: %s (%s)", user.host, reason)
	user.dead = true

	if user.connection != nil {
		user.connection.Close()
	}

	delete(userlist, user.id)
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

func NickHandler(user *User, line *message.Message) {
	oldnick := user.nick

	if len(line.Args) < 1 {
		user.FireNumeric(ERR_NONICKNAMEGIVEN)
		return
	}

	if NickHasBadChars(line.Args[0]) {
		user.FireNumeric(ERR_ERRONEOUSNICKNAME, line.Args[0])
		return
	}

	if GetUserByNick(line.Args[0]) != nil {
		user.FireNumeric(ERR_NICKNAMEINUSE, line.Args[0])
		return
	}

	if !user.nickset {
		user.nickset = true
	} else if user.registered {
		targets := []*User{}
		targets = append(targets, user)

		for _, k := range user.chanlist {
			targets = append(targets, k.GetUserList()...)
		}

		SendToMany(fmt.Sprintf(":%s NICK %s", user.GetHostMask(), line.Args[0]), targets)
	}

	user.nick = line.Args[0]

	logger.Printf("User %s changed nick to %s", oldnick, user.nick)

	if !user.registered && user.userset {
		user.UserRegistrationFinished()
	}
}

func UserHandler(user *User, line *message.Message) {
	if len(line.Args) < 4 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "USER")
		return
	}

	user.ident = line.Args[0]
	user.realname = line.Args[3]
	user.userset = true

	if !user.registered && user.nickset {
		user.UserRegistrationFinished()
	}

	time.Sleep(1 * time.Second) //XXX remove this?
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

func CommandNotFound(user *User, line *message.Message) {
	logger.Printf("User %s attempted unknown command %s", user.nick, line.Verb)

	user.FireNumeric(ERR_UNKNOWNCOMMAND, line.Verb)
}

func (user *User) GetHostMask() string {
	return fmt.Sprintf("%s!%s@%s", user.nick, user.ident, user.host)
}

func JoinHandler(user *User, line *message.Message) {
	if len(line.Args) < 1 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "JOIN")
		return
	}

	for _, channame := range strings.Split(line.Args[0], ",") {
		if !ValidChanName(channame) {
			user.FireNumeric(ERR_NOSUCHCHANNEL, channame)
			return
		}

		//TODO: support channel keys

		channel := GetChannelByName(channame)
		if channel == nil {
			channel = NewChannel(channame)
		}

		if channel.HasMode("A") && !user.oper {
			//TODO definitely fire numeric for this
			logger.Printf("User %s tried to join %s while +A was set.", user.nick, channel.name)
			return
		}

		if channel.HasUser(user) {
			logger.Printf("User %s tried to join %s while already joined.", user.nick, channel.name)
			return //should this silently fail?
		}

		if channel.IsUserBanned(user) && !user.oper {
			user.FireNumeric(RPL_BANNEDFROMCHAN, channel.name)
			logger.Printf("User %s tried to join %s while banned.", user.nick, channel.name)
			return
		}

		channel.JoinUser(user)
		user.chanlist[channel.name] = channel

		logger.Printf("User %s joined %s", user.nick, channel.name)
	}
}

func LusersHandler(user *User, line *message.Message) {
	user.FireNumeric(RPL_LUSERCLIENT, len(userlist), 1, 1)
	user.FireNumeric(RPL_LUSEROP, opercount)
	user.FireNumeric(RPL_LUSERCHANNELS, len(chanlist))
	user.FireNumeric(RPL_LUSERME, len(userlist), 1)
}

func PartHandler(user *User, line *message.Message) {
	if len(line.Args) < 1 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "PART")
		return
	}

	var reason string

	if len(line.Args) > 1 {
		reason = line.Args[1]
	} else {
		reason = config.DefaultPartReason
	}

	channel := GetChannelByName(line.Args[0])

	if channel != nil {
		channel.SendLinef(":%s PART %s :%s", user.GetHostMask(), channel.name, reason)
		delete(channel.userlist, user.id)
		delete(user.chanlist, channel.name)
		delete(channel.usermodes, user)
		logger.Printf("User %s PART %s: %s", user.nick, channel.name, reason)
		channel.ShouldIDie()
	} else {
		user.FireNumeric(ERR_NOSUCHCHANNEL, line.Args[0])
	}
}

func PrivmsgHandler(user *User, line *message.Message) {
	if len(line.Args) < 2 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "PRIVMSG")
		return
	}

	//is ValidChanName even needed here anymore?
	if ValidChanName(line.Args[0]) { //TODO part of this should be sent to the channel "object"
		//presumably a channel
		j := GetChannelByName(line.Args[0])

		if j != nil {
			if j.HasMode("n") && !user.IsIn(j) {
				user.FireNumeric(ERR_CANNOTSENDTOCHAN, j.name)
				return
			}

			userpriv := j.GetUserPriv(user)

			if j.HasMode("m") && userpriv < 10 {
				user.FireNumeric(ERR_CANNOTSENDTOCHAN, j.name)
				return
			}

			if j.IsUserBanned(user) && userpriv < 10 {
				user.FireNumeric(ERR_CANNOTSENDTOCHAN, j.name)
				return
			}

			//channel exists, send the message
			msg := line.Args[1]

			c, _ := j.GetCount()
			AddToMode4Cache(user, c, j)

			list := j.GetUserList()

			for _, l := range list {
				if l != user {
					if j.HasMode("4") {
						Mode4CacheMutex.Lock()

						var h bool
						var num int64

						for e := Mode4Cache.Front(); e != nil; e = e.Next() {
							ci := e.Value.(Mode4CacheItem)
							if ci.channel == j && strings.Contains(msg, fmt.Sprintf("%d", ci.number)) && ci.user == l {
								h = true
								num = ci.number

								break
							}
						}

						Mode4CacheMutex.Unlock()

						if h {
							l.SendLinef(":%s PRIVMSG %s :%s", fmt.Sprintf("%d!%d@%d", c, c, c), j.name, strings.Replace(msg, fmt.Sprintf("%d", num), l.nick, -1))
						} else {
							l.SendLinef(":%s PRIVMSG %s :%s", fmt.Sprintf("%d!%d@%d", c, c, c), j.name, msg)
						}
					} else {
						l.SendLinef(":%s PRIVMSG %s :%s", user.GetHostMask(), j.name, msg)
					}
				}
			}

			var loggerchan bool

			for _, testc := range config.LogChannels {
				if GetChannelByName(testc) == j {
					loggerchan = true
				}
			}

			//TODO: remove?
			if !loggerchan && !config.Privacy {
				logger.Printf("User %s CHANMSG %s: %s", user.nick, j.name, msg)
			}

			return
		} else {
			user.FireNumeric(ERR_NOSUCHCHANNEL, line.Args[0])

			return
		}
	}

	//maybe its a user
	target := GetUserByNick(line.Args[0])

	if target != nil {
		msg := line.Args[1]
		target.SendLinef(":%s PRIVMSG %s :%s", user.GetHostMask(), target.nick, msg)
	}
}

func TopicHandler(user *User, line *message.Message) {
	if len(line.Args) < 1 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "TOPIC")
		return
	}

	k := GetChannelByName(line.Args[0])

	if k == nil {
		user.FireNumeric(ERR_NOSUCHCHANNEL, line.Args[0])
		return
	}

	if len(line.Args) < 2 {
		k.FireTopic(user)
		return
	}

	if k.GetUserPriv(user) < 100 && k.HasMode("t") {
		return //doesn't have privs to change channel
		// TODO fire the correct numeric
	}

	msg := line.Args[1]

	k.SetTopic(msg, user.GetHostMask())
}

func ModeHandler(user *User, line *message.Message) {
	if len(line.Args) < 1 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "MODE")

		return
	}

	if ChanUserNone(line.Args[0]) == 1 {
		channel := GetChannelByName(line.Args[0])

		if len(line.Args) < 3 {
			//just digging around...
			channel.FireModes(user)
		} else {
			s := line.Args[1]
			mode := 0
			mcounter := 0

			var targs []string

			if len(line.Args) > 3 {
				targs = line.Args[2:]
			}

			for _, k := range s {
				switch k {
				case '+':
					mode = 2
					break
				case '-':
					mode = 1
					break
				case 'o', 'v':
					if len(targs)-1 < mcounter {
						user.FireNumeric(ERR_NEEDMOREPARAMS, "MODE")
						break
					}

					target := GetUserByNick(targs[mcounter])

					if target == nil {
						user.FireNumeric(ERR_NOSUCHNICK, line.Args[mcounter])
						mcounter = +1
						break
					}

					if !channel.HasUser(target) {
						user.FireNumeric(ERR_USERNOTINCHANNEL, target.nick, channel.name)
						mcounter = +1
						break
					}

					if mode == 2 {
						channel.SetUmode(target, user, string(k))
						mcounter = +1
						break
					}

					if mode == 1 {
						channel.UnsetUmode(target, user, string(k))
						mcounter = +1
						break
					}

					break
				case 'b':
					if len(targs)-1 < mcounter {
						channel.FireBanlist(user)
						break
					}

					if mode == 2 {
						channel.SetBan(targs[mcounter], user)
						mcounter++
						break
					}

					if mode == 1 {
						channel.UnsetBan(targs[mcounter], user)
						mcounter++
						break
					}

				case 't', 'n', 'm', 'A', '4':
					if mode == 2 {
						channel.SetMode(string(k), user)
					} else if mode == 1 {
						channel.UnsetMode(string(k), user)
					}
					break
				}
			}
		}
	}
}

func (user *User) IsIn(channel *Channel) bool {
	for _, k := range user.chanlist {
		if k == channel {
			return true
		}
	}
	return false
}

func PingHandler(user *User, line *message.Message) {
	if len(line.Args) < 1 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "PING")
		return
	}

	user.SendLinef(":%s PONG %s :%s", config.ServerName, config.ServerName, line.Args[0])
}

func WhoHandler(user *User, line *message.Message) {
	if len(line.Args) < 1 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "WHO")
		return
	}

	whotype := ChanUserNone(line.Args[0])

	if whotype == 0 {
		//its a channel
		k := GetChannelByName(line.Args[0])
		line.Args[0] = k.name // normalizing case

		for _, j := range k.userlist {
			h := "H" + k.GetUserPrefix(j) // TODO: add away status
			user.FireNumeric(RPL_WHOREPLY, k.name, j.ident, j.host, config.ServerName, j.nick, h, ":0", j.realname)
		}

	} else if whotype == 2 {
		//user
		k := GetUserByNick(line.Args[0])
		line.Args[0] = k.nick
		user.FireNumeric(RPL_WHOREPLY, "*", k.ident, k.host, config.ServerName, k.nick, "H", ":0", k.realname) // TODO: add away status
	}

	user.FireNumeric(RPL_ENDOFWHO, line.Args[0])
}

func KickHandler(user *User, line *message.Message) {
	if len(line.Args) < 2 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "KICK")
	}

	channel := GetChannelByName(line.Args[1])

	if channel == nil {
		user.FireNumeric(ERR_NOSUCHCHANNEL, line.Args[1])
		return
	}

	target := GetUserByNick(line.Args[2])

	if target == nil {
		user.FireNumeric(ERR_NOSUCHNICK, line.Args[2])
		return
	}

	if channel.GetUserPriv(user) < 100 {
		user.FireNumeric(ERR_CHANOPRIVSNEEDED, channel.name)
		return
	}

	if !channel.HasUser(target) {
		user.FireNumeric(ERR_USERNOTINCHANNEL, target.nick, channel.name)
		return
	}

	if user.system {
		// TODO: numeric here
		return //This could be bad.
	}

	var reason string

	if len(line.Args) > 2 {
		reason = line.Args[2]
	} else {
		reason = config.DefaultKickReason
	}

	channel.SendLinef(":%s KICK %s %s :%s", user.GetHostMask(), channel.name, target.nick, reason)
	delete(channel.userlist, target.id)
	delete(target.chanlist, channel.name)
	delete(channel.usermodes, target)
	logger.Printf("%s kicked %s from %s", user.nick, target.nick, channel.name)

	channel.ShouldIDie()
}

func ListHandler(user *User, line *message.Message) {
	// TODO: extended LIST support or ALIS searching
	user.FireNumeric(RPL_LISTSTART)

	for _, k := range chanlist {
		user.FireNumeric(RPL_LIST, k.name, len(k.userlist), k.topic)
	}

	user.FireNumeric(RPL_LISTEND)
}

func OperHandler(user *User, line *message.Message) {
	if len(line.Args) < 2 {
		CommandNotFound(user, line)
		return
	}

	//TODO: Add password hashing via b2sum -- Xena
	if config.Opers[line.Args[0]] == line.Args[1] {
		user.oper = true
		opercount++
		user.FireNumeric(RPL_YOUREOPER)
	} else {
		CommandNotFound(user, line)
	}
}

func NamesHandler(user *User, line *message.Message) {
	if len(line.Args) < 1 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "NAMES")
		return
	}

	channel := GetChannelByName(line.Args[0])

	if channel == nil {
		user.FireNumeric(ERR_NOSUCHCHANNEL, line.Args[0])
		return
	}

	channel.FireNames(user)
}

func RehashHandler(user *User, line *message.Message) {
	if user.oper {
		SetupConfig(*configFlag)
		user.FireNumeric(RPL_REHASHING, *configFlag)
		logger.Printf("OPER %s requested rehash...", user.nick)
	} else {
		CommandNotFound(user, line)
	}
}

func ShutdownHandler(user *User, line *message.Message) {
	//TODO: rename to DIE -- Xena
	if user.oper {
		logger.Printf("Shutdown requested by OPER %s", user.nick)

		for _, k := range userlist {
			k.Quit(fmt.Sprintf("Server is being shutdown by %s", user.nick))
		}

		os.Exit(0)
	} else {
		CommandNotFound(user, line)
	}
}

func KillHandler(user *User, line *message.Message) {
	if user.oper {
		if len(line.Args) < 2 {
			user.FireNumeric(ERR_NEEDMOREPARAMS, "KILL")
			return
		}

		var reason string

		target := GetUserByNick(line.Args[0])

		if target == nil {
			user.FireNumeric(ERR_NOSUCHNICK, line.Args[0])
			return
		}

		if len(line.Args) > 2 {
			reason = line.Args[1]
		} else {
			reason = config.DefaultKillReason
		}

		target.Quit(fmt.Sprintf("KILL: %s", reason))
		logger.Printf("oper %s killed %s (%s)", user.nick, target.nick, reason)

	} else {
		CommandNotFound(user, line)
	}
}

func WhoisHandler(user *User, line *message.Message) {
	if len(line.Args) < 1 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "WHOIS")
		return
	}

	target := GetUserByNick(line.Args[0])

	if target == nil {
		user.FireNumeric(ERR_NOSUCHNICK, line.Args[0])

		return
	}

	var buf bytes.Buffer

	// TODO: +s channels
	for _, k := range target.chanlist {
		buf.WriteString(k.name + " ")
	}

	chanstring := strings.TrimSpace(buf.String())

	user.FireNumeric(RPL_WHOISUSER, target.nick, target.ident, target.host, target.realname)
	user.FireNumeric(RPL_WHOISCHANNELS, target.nick, chanstring)
	user.FireNumeric(RPL_WHOISSERVER, target.nick, config.ServerName, config.ServerDescription)

	if target.oper {
		user.FireNumeric(RPL_WHOISOPERATOR, target.nick)
	}

	if user.oper || user == target {
		user.FireNumeric(RPL_WHOISHOST, target.nick, target.realhost, target.realip)
	} else {
		user.FireNumeric(RPL_WHOISHOST, target.nick, target.host, target.ip)
	}

	user.FireNumeric(RPL_ENDOFWHOIS, target.nick)
}

func AddToMode4Cache(user *User, number int64, channel *Channel) {
	Mode4CacheMutex.Lock()
	defer Mode4CacheMutex.Unlock()
	if Mode4Cache.Len() > 1000 {
		for i := 0; i < 500; i++ {
			Mode4Cache.Remove(Mode4Cache.Back())
		}
	}
	k := Mode4CacheItem{}
	k.user = user
	k.number = number
	k.channel = channel
	Mode4Cache.PushFront(k)
}

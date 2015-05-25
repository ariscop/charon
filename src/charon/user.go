package main

import (
	"bufio"
	"bytes"
	"fmt"
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

func QuitCommandHandler(user *User, args []string) {
	var reason string
	if len(args) > 1 {
		args[1] = strings.TrimPrefix(args[1], ":")
		reason = strings.Join(args[1:], " ")
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
		ProcessLine(user, line)
	}
}
func NickHandler(user *User, args []string) {
	oldnick := user.nick
	if len(args) < 2 {
		user.FireNumeric(ERR_NONICKNAMEGIVEN)
		return
	}
	if NickHasBadChars(args[1]) {
		user.FireNumeric(ERR_ERRONEOUSNICKNAME, args[1])
		return
	}
	if GetUserByNick(args[1]) != nil {
		user.FireNumeric(ERR_NICKNAMEINUSE, args[1])
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
		SendToMany(fmt.Sprintf(":%s NICK %s", user.GetHostMask(), args[1]), targets)
	}
	user.nick = args[1]
	logger.Printf("User %s changed nick to %s", oldnick, user.nick)
	if !user.registered && user.userset {
		user.UserRegistrationFinished()
	}
}

func UserHandler(user *User, args []string) {
	if len(args) < 5 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "USER")
		return
	}
	user.ident = args[1]
	args[4] = strings.TrimPrefix(args[4], ":")
	user.realname = strings.TrimSpace(strings.Join(args[4:], " "))
	user.userset = true
	if !user.registered && user.nickset {
		user.UserRegistrationFinished()
	}

	time.Sleep(1 * time.Second)
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

	LusersHandler(user, []string{})
	for _, k := range config.AutoJoin {
		JoinHandler(user, []string{"JOIN", k})
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

func CommandNotFound(user *User, args []string) {
	logger.Printf("User %s attempted unknown command %s", user.nick, args[0])
	user.FireNumeric(ERR_UNKNOWNCOMMAND, args[0])
}

func (user *User) GetHostMask() string {
	return fmt.Sprintf("%s!%s@%s", user.nick, user.ident, user.host)
}

func JoinHandler(user *User, args []string) {
	if len(args) < 2 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "JOIN")
		return
	}

	for _, channame := range strings.Split(args[1], ",") {
		if !ValidChanName(channame) {
			user.FireNumeric(ERR_NOSUCHCHANNEL, channame)
			return
		}
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

func LusersHandler(user *User, args []string) {
	user.FireNumeric(RPL_LUSERCLIENT, len(userlist), 1, 1)
	user.FireNumeric(RPL_LUSEROP, opercount)
	user.FireNumeric(RPL_LUSERCHANNELS, len(chanlist))
	user.FireNumeric(RPL_LUSERME, len(userlist), 1)
}

func PartHandler(user *User, args []string) {
	if len(args) < 2 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "PART")
		return
	}
	var reason string
	if len(args) > 2 {
		args[2] = strings.TrimPrefix(args[2], ":")
		reason = strings.Join(args[2:], " ")
	} else {
		reason = config.DefaultPartReason
	}
	channel := GetChannelByName(args[1])
	if channel != nil {
		channel.SendLinef(":%s PART %s :%s", user.GetHostMask(), channel.name, reason)
		delete(channel.userlist, user.id)
		delete(user.chanlist, channel.name)
		delete(channel.usermodes, user)
		logger.Printf("User %s PART %s: %s", user.nick, channel.name, reason)
		channel.ShouldIDie()
	} //else?
}

func PrivmsgHandler(user *User, args []string) {
	if len(args) < 3 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "PRIVMSG")
		return
	}
	//is ValidChanName even needed here anymore?
	if ValidChanName(args[1]) { //TODO part of this should be sent to the channel "object"
		//presumably a channel
		j := GetChannelByName(args[1])
		if j != nil {
			if j.HasMode("n") && !user.IsIn(j) && !user.oper {
				user.FireNumeric(ERR_CANNOTSENDTOCHAN, j.name)
				return
			}

			userpriv := j.GetUserPriv(user)

			if j.HasMode("m") && userpriv < 10 && !user.oper {
				user.FireNumeric(ERR_CANNOTSENDTOCHAN, j.name)
				return
			}

			if j.IsUserBanned(user) && userpriv < 10 && !user.oper {
				user.FireNumeric(ERR_CANNOTSENDTOCHAN, j.name)
				return
			}

			//channel exists, send the message
			msg := FormatMessageArgs(args)

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
			if !loggerchan && !config.Privacy {
				logger.Printf("User %s CHANMSG %s: %s", user.nick, j.name, msg)
			}
			return
		} else {
			user.FireNumeric(ERR_NOSUCHCHANNEL, args[1])
			return
		}
	} else {
		//maybe its a user
		target := GetUserByNick(args[1])
		if target != nil {
			msg := FormatMessageArgs(args)
			target.SendLinef(":%s PRIVMSG %s :%s", user.GetHostMask(), target.nick, msg)
			if !config.Privacy {
				logger.Printf("User %s PRIVMSG %s: %s", user.nick, target.nick, msg)
			}
		}
	}
}

func TopicHandler(user *User, args []string) {
	if len(args) < 2 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "TOPIC")
		return
	}
	k := GetChannelByName(args[1])
	if k == nil {
		user.FireNumeric(ERR_NOSUCHCHANNEL, args[1])
		return
	}
	if len(args) < 3 {
		k.FireTopic(user)
		return
	}
	if k.GetUserPriv(user) < 100 && k.HasMode("t") {
		return //doesn't have privs to change channel
		// TODO fire the correct numeric
	}
	msg := FormatMessageArgs(args)
	k.SetTopic(msg, user.GetHostMask())
}

func ModeHandler(user *User, args []string) {
	if len(args) < 2 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "MODE")
		return
	}
	if ChanUserNone(args[1]) == 1 {
		channel := GetChannelByName(args[1])
		if len(args) < 3 {
			//just digging around...
			channel.FireModes(user)
			logger.Printf("User %s requested modes for %s", user.nick, channel.name)
		} else {
			s := args[2]
			mode := 0
			mcounter := 0
			var targs []string
			if len(args) > 3 {
				targs = args[3:]
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
						user.FireNumeric(ERR_NOSUCHNICK, args[mcounter])
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

func PingHandler(user *User, args []string) {
	if len(args) < 2 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "PING")
		return
	}
	args[1] = strings.TrimPrefix(args[1], ":")
	user.SendLinef(":%s PONG %s :%s", config.ServerName, config.ServerName, args[1])
}

func WhoHandler(user *User, args []string) {
	if len(args) < 2 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "WHO")
		return
	}
	whotype := ChanUserNone(args[1])
	if whotype == 1 {
		//its a channel
		k := GetChannelByName(args[1])
		args[1] = k.name
		for _, j := range k.userlist {
			h := "H" + k.GetUserPrefix(j)
			user.FireNumeric(RPL_WHOREPLY, k.name, j.ident, j.host, config.ServerName, j.nick, h, ":0", j.realname)
		}
	} else if whotype == 2 {
		//user
		k := GetUserByNick(args[1])
		args[1] = k.nick
		user.FireNumeric(RPL_WHOREPLY, "*", k.ident, k.host, config.ServerName, k.nick, "H", ":0", k.realname)
	}
	user.FireNumeric(RPL_ENDOFWHO, args[1])
}

func KickHandler(user *User, args []string) {
	if len(args) < 3 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "KICK")
	}
	channel := GetChannelByName(args[1])
	if channel == nil {
		user.FireNumeric(ERR_NOSUCHCHANNEL, args[1])
		return
	}
	target := GetUserByNick(args[2])
	if target == nil {
		user.FireNumeric(ERR_NOSUCHNICK, args[2])
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
		return //This could be bad.
	}
	var reason string
	if len(args) > 3 {
		reason = strings.Join(args[3:], " ")
		reason = strings.TrimPrefix(reason, ":")
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

func ListHandler(user *User, args []string) {
	user.FireNumeric(RPL_LISTSTART)
	for _, k := range chanlist {
		user.FireNumeric(RPL_LIST, k.name, len(k.userlist), k.topic)
	}
	user.FireNumeric(RPL_LISTEND)
}

func OperHandler(user *User, args []string) {
	if len(args) < 3 {
		CommandNotFound(user, args)
		return
	}

	//TODO: Add password hashing via b2sum -- Xena
	if config.Opers[args[1]] == args[2] {
		user.oper = true
		opercount++
		user.FireNumeric(RPL_YOUREOPER)
	} else {
		CommandNotFound(user, args)
	}
}

func NamesHandler(user *User, args []string) {
	if len(args) < 2 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "NAMES")
		return
	}
	channel := GetChannelByName(args[1])
	if channel == nil {
		user.FireNumeric(ERR_NOSUCHCHANNEL, args[1])
		return
	}
	channel.FireNames(user)
}

func RehashHandler(user *User, args []string) {
	if user.oper {
		SetupConfig(*configFlag)
		user.FireNumeric(RPL_REHASHING, *configFlag)
		logger.Printf("OPER %s requested rehash...", user.nick)
	} else {
		CommandNotFound(user, args)
	}
}

func ShutdownHandler(user *User, args []string) {
	//TODO: rename to DIE -- Xena
	if user.oper {
		logger.Printf("Shutdown requested by OPER %s", user.nick)
		for _, k := range userlist {
			k.Quit(fmt.Sprintf("Server is being shutdown by %s", user.nick))
		}
		os.Exit(0)
	} else {
		CommandNotFound(user, args)
	}
}

func KillHandler(user *User, args []string) {
	if user.oper {
		if len(args) < 2 {
			user.FireNumeric(ERR_NEEDMOREPARAMS, "KILL")
			return
		} else {
			var reason string
			bill := GetUserByNick(args[1])
			if bill == nil {
				user.FireNumeric(ERR_NOSUCHNICK, args[1])
				return
			} else {
				if len(args) > 2 {
					reason = strings.Join(args[2:], " ")
					reason = strings.TrimPrefix(reason, ":")
				} else {
					reason = config.DefaultKillReason
				}
				bill.Quit(fmt.Sprintf("KILL: %s", reason))
				logger.Printf("oper %s killed %s (%s)", user.nick, bill.nick, reason)
			}
		}
	} else {
		CommandNotFound(user, args)
	}
}

func WhoisHandler(user *User, args []string) {
	if len(args) < 2 {
		user.FireNumeric(ERR_NEEDMOREPARAMS, "WHOIS")
		return
	}
	target := GetUserByNick(args[1])
	if target == nil {
		user.FireNumeric(ERR_NOSUCHNICK, args[1])
		return
	}
	var buf bytes.Buffer
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

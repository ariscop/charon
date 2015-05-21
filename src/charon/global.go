package main

import (
	"container/list"
	"os"
	"sync"
	"time"

	"github.com/garyburd/redigo/redis"
)

const (
	software       = "charon"
	softwarev      = "v0.1"
	isupport       = "NAMESX CHANTYPES=#& PREFIX=(ov)@+"
	conf_file_name = "charon.json"
)

type Mode4CacheItem struct {
	user    *User
	number  int64
	channel *Channel
}

var (
	Mode4CacheMutex   = &sync.Mutex{}
	Mode4Cache        = list.New()
	RedisPool         *redis.Pool
	StartupIncomplete = true //used to determine if the ircd is up and running yet
	valid_chan_prefix = []string{"#", "&"}
	global_bad_chars  = []string{","}
	config            *configuration
	counter           = 1
	userlist          = make(map[int]*User)
	chanlist          = make(map[string]*Channel)
	maxUsers          int
	maxRoutines       int
	epoch             = time.Now()
	opercount         = 0
	SystemUser        = &User{
		user:       "system",
		ident:      "system",
		id:         0,
		realname:   "system user",
		userset:    true,
		registered: true,
		ip:         "127.0.0.1",
		realip:     "127.0.0.1",
		epoch:      time.Now(),
		chanlist:   make(map[string]*Channel),
		oper:       true,
		system:     true,
	}
	DefaultConf = &configuration{
		ServerName:         "test.net.local",
		ServerDescription:  "A test server",
		DefaultKickReason:  "Your behavior is not conductive of the desired environment.",
		DefaultKillReason:  "Your behavior is not conductive of the desired environment.",
		DefaultQuitReason:  "Leaving",
		DefaultPartReason:  "Leaving",
		PingTime:           45,
		PingCheckTime:      20,
		ResolveHosts:       true,
		DefaultCmode:       "nt",
		StatTime:           30,
		Debug:              false,
		Cloaking:           false,
		OpersKickable:      false,
		Salt:               "default",
		ListenIPs:          []string{"0.0.0.0"},
		ListenPorts:        []int{6667, 6668, 6669},
		LogChannels:        []string{"#log", "#opers"},
		Opers:              map[string]string{"default": "password"},
		Privacy:            false,
		AutoJoin:           []string{"#default"},
		SystemJoinChannels: false,
		Logfile:            "charon.log",
		RedisHost:          "127.0.0.1",
		RedisPort:          6379,
	}
	logger      = &Elog{}
	LoggingFile *os.File
)

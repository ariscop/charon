package main

import oldlogger "log"
import "strings"
import "fmt"
import "time"

type Elog struct {
	//nothing
}

func (elog *Elog) Printf(msg string, args ...interface{}) {
	oldlogger.Printf(msg, args...)
	WriteToLogFile(msg, args...)
	SendLineToLogChannels(fmt.Sprintf(msg, args...))
}

func SendLineToLogChannels(msg string) {
	if StartupIncomplete {
		return
	}
	msg2 := strings.Split(msg, " ")
	for _, k := range config.LogChannels {
		sender := []string{"PRIVMSG", k}
		sender = append(sender, msg2...)
		SystemUser.PrivmsgHandler(sender)
	}
}

func WriteToLogFile(msg string, args ...interface{}) {
	if config == nil {
		return
	}
	if config.Logfile != "" && LoggingFile != nil {
		loggerstr := fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC1123), fmt.Sprintf(msg, args...))
		_, err := LoggingFile.WriteString(loggerstr)
		if err != nil {
			config.Logfile = ""
			logger.Printf("ERROR: %s", err.Error())
			logger.Printf("Error writing to Logfile %s, disabling file loggerging", config.Logfile)
		}
	}
}

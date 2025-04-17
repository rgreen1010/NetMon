#pragma once

#include "NetMon.h"

#define DEBUGMSG	1
#define ERRORMSG	2

#define DEBUG_LOGDIR	"Debug"
#define DEBUG_LOGFILE	"NetMon-Debug"



class LogMessages {

public:
	LogMessages();
	~LogMessages();

	int logMessage(int type, std::string msg) {
		std::string logfile;
		// Place holder
		switch (type) {
		case DEBUGMSG:
			logfile = DEBUG_LOGFILE;
			break;
		case ERRORMSG:
			break;
		default:
			break;

		}
		return 0;
	}
};

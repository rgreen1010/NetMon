#pragma once

#include "NetMon.h"

struct registrantInfo {
	std::string name;
	std::string	address;
	std::string	country;
	std::string	contact;
	std::string organization;
};
typedef struct registrantInfo RegistrantInfo;
struct whoisInfo {
	RegistrantInfo  registrant;
	std::string		details;
	std::string		networkCidr;
	std::string		ip;
	std::string		domain;
	time_t			lookupTime;
};
typedef struct whoisInfo WhoisInfo;

class WhoisService {

	public:
		WhoisService();
		~WhoisService();

		// Main lookup method
		WhoisInfo lookup(const std::string& ipAddress);

		// Timeout settings
		void setConnectionTimeout(int seconds);
		void setResponseTimeout(int seconds);

		// WHOIS server selection methods
		void setPreferredServer(const std::string& server);
		std::string determineWhoisServer(const std::string& ipAddress);

		// Error handling
		bool hasError() const;
		std::string getLastError() const;

		WhoisInfo		performWhoisLookup(std::string ip);
		RegistrantInfo	getRegistrantInfo();
		int				setRegistrantInfo(RegistrantInfo inInfo);
		//int				setRegistrantName(std::string name);
		//int				setRegistrantAddress(std::string addressd);
		//int				setRegistrantContact(std::string contact);
		std::string	getnetworkCidr();
		int			setnetworkCidr(std::string cidr);
		std::string getDomain();
		int			setDomain(std::string domain);
		std::string getDetails();
		int			setDetails(std::string details);
		time_t		getLookupTime();
		int			setLookupTime(time_t lookupTime);

	private:
		WhoisInfo networkWhois;

		int connectionTimeoutSecs;
		int responseTimeoutSecs;
		std::string preferredServer;
		std::string lastError;

		// Private helper methods
		std::string sendWhoisQuery(const std::string& server, const std::string& query);
		WhoisInfo parseWhoisResponse(const std::string& response, const std::string& ipAddress);
		bool isIPv4(const std::string& ipAddress);
		bool isIPv6(const std::string& ipAddress);
		std::string getServerForTLD(const std::string& tld);

		// Socket handling helpers
		SOCKET createSocket();
		bool connectToServer(SOCKET sock, const std::string& server);
		bool sendRequest(SOCKET sock, const std::string& query);
		std::string receiveResponse(SOCKET sock);

};
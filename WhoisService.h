#pragma once

#include "NetMon.h"

#define WHOIS_QUERY_LIMIT   50

class WhoisService {
public:
    // Represents the result of a WHOIS lookup
    struct WhoisInfo {
        std::string ip;
        std::string networkCidr;
        std::string registrant;
        std::string organization;
        std::string country;
        std::string abuseContact;
        std::string details;  // Raw or additional information
        time_t lookupTime;

        WhoisInfo() : lookupTime(time(nullptr)) {}
    };

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

private:
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
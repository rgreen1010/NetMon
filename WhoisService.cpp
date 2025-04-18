
/*
* 
*/
#include "NetMon.h"

WhoisService::WhoisService()
    : connectionTimeoutSecs(5), responseTimeoutSecs(10), preferredServer("") {
    // Initialize Windows sockets if on Windows
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        lastError = "Failed to initialize Winsock";
    }
#endif
}

WhoisService::~WhoisService() {
    // Cleanup Windows sockets if on Windows
#ifdef _WIN32
    WSACleanup();
#endif
}

/*
* ------------------ Whois Lookup ------------------------
*/
WhoisService::WhoisInfo WhoisService::lookup(const std::string& ipAddress) {
    WhoisInfo info;
    info.ip = ipAddress;

    // Validate IP address
    if (!isIPv4(ipAddress) && !isIPv6(ipAddress)) {
        lastError = "Invalid IP address format";
        return info;
    }

    // Determine which WHOIS server to query
    std::string server = preferredServer;
    if (server.empty()) {
        server = determineWhoisServer(ipAddress);
    }

    if (server.empty()) {
        lastError = "Could not determine appropriate WHOIS server";
        return info;
    }

    // Send the query and get response
    std::string response = sendWhoisQuery(server, ipAddress);

    if (response.empty()) {
        // lastError already set in sendWhoisQuery
        return info;
    }

    // Parse the response
    return parseWhoisResponse(response, ipAddress);
}

std::string WhoisService::determineWhoisServer(const std::string& ipAddress) {
    // For IPv4 addresses
    if (isIPv4(ipAddress)) {
        // IANA maintains the global WHOIS server for IP allocations
        return "whois.iana.org";
    }
    // For IPv6 addresses
    else if (isIPv6(ipAddress)) {
        return "whois.iana.org";
    }

    return "";
}

std::string WhoisService::sendWhoisQuery(const std::string& server, const std::string& query) {
    SOCKET sock = createSocket();
    if (sock == INVALID_SOCKET) {
        return "";
    }

    // Set socket timeout options
    struct timeval timeout;
    timeout.tv_sec = connectionTimeoutSecs;
    timeout.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
        lastError = "Failed to set socket receive timeout";
        closesocket(sock);
        return "";
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
        lastError = "Failed to set socket send timeout";
        closesocket(sock);
        return "";
    }

    // Connect to the WHOIS server
    if (!connectToServer(sock, server)) {
        closesocket(sock);
        return "";
    }

    // Send the query
    if (!sendRequest(sock, query + "\r\n")) {
        closesocket(sock);
        return "";
    }

    // Receive the response
    std::string response = receiveResponse(sock);

    // Close the socket
    closesocket(sock);

    return response;
}

WhoisService::WhoisInfo WhoisService::parseWhoisResponse(const std::string& response,
    const std::string& ipAddress) {
    WhoisInfo info;
    info.ip = ipAddress;
    info.details = response;

    // Parse the response to extract relevant information
    // This is a simplified example - actual parsing would be more complex

    std::istringstream responseStream(response);
    std::string line;

    while (std::getline(responseStream, line)) {
        // Convert line to lowercase for case-insensitive matching
        std::string lowerLine = line;
        std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(), ::tolower);

        // Look for common WHOIS response fields
        if (lowerLine.find("cidr") != std::string::npos ||
            lowerLine.find("inetnum") != std::string::npos ||
            lowerLine.find("netrange") != std::string::npos) {

            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos && colonPos + 1 < line.length()) {
                info.networkCidr = line.substr(colonPos + 1);
                // Trim leading/trailing whitespace
                info.networkCidr.erase(0, info.networkCidr.find_first_not_of(" \t"));
                info.networkCidr.erase(info.networkCidr.find_last_not_of(" \t") + 1);
            }
        }
        else if (lowerLine.find("registrant") != std::string::npos ||
            lowerLine.find("owner") != std::string::npos ||
            lowerLine.find("netname") != std::string::npos) {

            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos && colonPos + 1 < line.length()) {
                info.registrant = line.substr(colonPos + 1);
                // Trim
                info.registrant.erase(0, info.registrant.find_first_not_of(" \t"));
                info.registrant.erase(info.registrant.find_last_not_of(" \t") + 1);
            }
        }
        else if (lowerLine.find("organization") != std::string::npos ||
            lowerLine.find("orgname") != std::string::npos) {

            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos && colonPos + 1 < line.length()) {
                info.organization = line.substr(colonPos + 1);
                // Trim
                info.organization.erase(0, info.organization.find_first_not_of(" \t"));
                info.organization.erase(info.organization.find_last_not_of(" \t") + 1);
            }
        }
        else if (lowerLine.find("country") != std::string::npos) {
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos && colonPos + 1 < line.length()) {
                info.country = line.substr(colonPos + 1);
                // Trim
                info.country.erase(0, info.country.find_first_not_of(" \t"));
                info.country.erase(info.country.find_last_not_of(" \t") + 1);
            }
        }
        else if (lowerLine.find("abuse") != std::string::npos &&
            lowerLine.find("email") != std::string::npos) {

            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos && colonPos + 1 < line.length()) {
                info.abuseContact = line.substr(colonPos + 1);
                // Trim
                info.abuseContact.erase(0, info.abuseContact.find_first_not_of(" \t"));
                info.abuseContact.erase(info.abuseContact.find_last_not_of(" \t") + 1);
            }
        }

        // Check if we're being referred to another WHOIS server
        if (lowerLine.find("refer:") != std::string::npos ||
            lowerLine.find("whois:") != std::string::npos) {

            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos && colonPos + 1 < line.length()) {
                std::string referServer = line.substr(colonPos + 1);
                // Trim
                referServer.erase(0, referServer.find_first_not_of(" \t"));
                referServer.erase(referServer.find_last_not_of(" \t") + 1);

                // If we have a referral and little information, query the referred server
                if (info.registrant.empty() && info.organization.empty() && !referServer.empty()) {
                    std::string newResponse = sendWhoisQuery(referServer, ipAddress);
                    if (!newResponse.empty()) {
                        return parseWhoisResponse(newResponse, ipAddress);
                    }
                }
            }
        }
    }

    return info;
}

bool WhoisService::isIPv4(const std::string& ipAddress) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ipAddress.c_str(), &(sa.sin_addr)) == 1;
}

bool WhoisService::isIPv6(const std::string& ipAddress) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, ipAddress.c_str(), &(sa.sin6_addr)) == 1;
}

// Socket handling helpers
SOCKET WhoisService::createSocket() {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
#ifdef _WIN32
        lastError = "Socket creation failed with error: " + std::to_string(WSAGetLastError());
#else
        lastError = "Socket creation failed: " + std::string(strerror(errno));
#endif
        return INVALID_SOCKET;
    }
    return sock;
}

bool WhoisService::connectToServer(SOCKET sock, const std::string& server) {
    struct addrinfo hints, * result = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address
    int status = getaddrinfo(server.c_str(), "43", &hints, &result);
    if (status != 0) {
#ifdef _WIN32
        lastError = "getaddrinfo failed: " + std::to_string(status);
#else
        lastError = "getaddrinfo failed: " + std::string(gai_strerror(status));
#endif
        return false;
    }

    // Attempt to connect to the server
    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
#ifdef _WIN32
        lastError = "Connect failed with error: " + std::to_string(WSAGetLastError());
#else
        lastError = "Connect failed: " + std::string(strerror(errno));
#endif
        freeaddrinfo(result);
        return false;
    }

    freeaddrinfo(result);
    return true;
}

bool WhoisService::sendRequest(SOCKET sock, const std::string& query) {
    if (send(sock, query.c_str(), (int)query.length(), 0) == SOCKET_ERROR) {
#ifdef _WIN32
        lastError = "Send failed with error: " + std::to_string(WSAGetLastError());
#else
        lastError = "Send failed: " + std::string(strerror(errno));
#endif
        return false;
    }
    return true;
}

std::string WhoisService::receiveResponse(SOCKET sock) {
    std::string response;
    char buffer[4096];
    int bytesReceived;

    do {
        bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            response += buffer;
        }
        else if (bytesReceived == 0) {
            // Connection closed
            break;
        }
        else {
#ifdef _WIN32
            lastError = "Receive failed with error: " + std::to_string(WSAGetLastError());
#else
            lastError = "Receive failed: " + std::string(strerror(errno));
#endif
            return "";
        }
    } while (bytesReceived > 0);

    return response;
}

void WhoisService::setConnectionTimeout(int seconds) {
    connectionTimeoutSecs = seconds;
}

void WhoisService::setResponseTimeout(int seconds) {
    responseTimeoutSecs = seconds;
}

void WhoisService::setPreferredServer(const std::string& server) {
    preferredServer = server;
}

bool WhoisService::hasError() const {
    return !lastError.empty();
}

std::string WhoisService::getLastError() const {
    return lastError;
}
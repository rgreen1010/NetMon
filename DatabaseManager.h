#pragma once
/**
*  Database Manager classes, data structures and constants
*/
#include <mutex>

class DatabaseManager {
public:
    DatabaseManager(const std::string& dbPath = "network_monitor.db");
    ~DatabaseManager();

    // Database initialization
    bool initDatabase();

    // Raw conversation methods
    bool saveRawConversation(const ConversationData& data);
    bool saveRawConversations(const std::map<ConversationKey, ConversationData>& trafficData);
    std::vector<ConversationData> getRawConversations();
    bool deleteRawConversation(int id);

    // Conversation pair methods
    bool updateConversationPair(const std::string& sourceIp, const std::string& destIp,
        int sourcePort, int destPort, const std::string& protocol,
        long packetCount, long byteCount);
    std::vector<ConversationData> getConversationPairs(int limit = 1000, int offset = 0);
    ConversationData getConversationPairById(int id);
    int getConversationPairsCount();

    // Hostname methods
    bool updateHostname(const std::string& ip, const std::string& hostname);
    std::string getHostname(const std::string& ip);
    bool isHostnameUpToDate(const std::string& ip, int maxAgeDays = 7);
    std::vector<std::string> getIpsNeedingHostnameLookup(int maxAgeDays = 7, int limit = 100);
    std::map<std::string, std::string> getAllHostnames();


    // Whois database entries access methods use "new" WhoisService data structures
    bool updateWhoisInfo(const std::string& ip, const WhoisService::WhoisInfo& info);
    WhoisService::WhoisInfo getWhoisInfo(const std::string& ip);
    bool isWhoisInfoUpToDate(const std::string& ip, int maxAgeDays = 30);
    std::vector<std::string> getIpsNeedingWhoisLookup(int maxAgeDays = 30, int limit = 50);

    // Utility methods
    std::vector<std::string> getUniqueIpAddresses(int limit = 1000);
    std::vector<std::string> getSourceIps(int limit = 500);
    std::vector<std::string> getDestinationIps(int limit = 500);
    std::vector<std::string> getProtocols();
    std::vector<ConversationData> searchConversations(const std::string& sourceIp,
        const std::string& destIp,
        int sourcePort = -1,
        int destPort = -1,
        const std::string& protocol = "");

    // Statistics methods
    std::vector<std::pair<std::string, long>> getTopSourceIps(int limit = 10);
    std::vector<std::pair<std::string, long>> getTopDestinationIps(int limit = 10);
    std::vector<std::pair<int, long>> getTopPorts(int limit = 10);
    std::vector<std::pair<std::string, long>> getTopProtocols();
    long getTotalPackets();
    long getTotalBytes();

private:
    sqlite3* db;
    std::mutex dbMutex;

    // Helper methods
    bool executeQuery(const std::string& sql);
    bool beginTransaction();
    bool commitTransaction();
    bool rollbackTransaction();
    std::string getTimestampString();
};
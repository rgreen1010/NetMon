#pragma once
#include "NetMon.h"

/*
* 
*/
class NetworkCapture {
public:
    NetworkCapture(std::shared_ptr<DatabaseManager> dbManager);
    ~NetworkCapture();

    // Interface methods
    std::vector<std::string> getNetworkInterfaces();
    bool setInterface(const std::string& interfaceName);
    std::string getCurrentInterface() const;

    // Capture control
    bool startCapture();
    void stopCapture();
    bool isCapturing() const;

    // Data access (thread-safe)
    std::map<ConversationKey, ConversationData> getCurrentTrafficData();
    void clearTrafficData();

    // Event handlers
    void setTrafficUpdateCallback(std::function<void()> callback);

private:
    std::shared_ptr<DatabaseManager> dbManager;
    pcap_t* pcapHandle;
    std::string interfaceName;

    std::thread captureThread;
    std::atomic<bool> running;

    std::map<ConversationKey, ConversationData> trafficData;
    std::mutex trafficMutex;

    std::function<void()> trafficUpdateCallback;

    // Private methods
    void captureThreadFunction();
    void processPacket(const struct pcap_pkthdr* header, const u_char* packet);
    bool extractConversationData(const u_char* packet, ConversationKey& key, ConversationData& data);
    void saveTrafficDataToDb();
};
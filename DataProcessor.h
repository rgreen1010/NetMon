#pragma once

#include "NetMon.h"

class DataProcessor {
public:
    DataProcessor(std::shared_ptr<DatabaseManager> dbManager);
    ~DataProcessor();

    // Control methods
    bool start();
    void stop();
    bool isRunning() const;

    // Processing methods
    void processRawConversations();
    void updateHostnames(int maxItems = 100);
    void updateWhoisInfoEntries(int maxItems = 50, DatabaseManager& dbManager );

    // DNS and WHOIS lookup methods
    std::string performDnsLookup(const std::string& ip);
    std::string performLocalLookup(const std::string& ip);
    WhoisService::WhoisInfo performWhoisLookup(const std::string& ip);

private:
    std::shared_ptr<DatabaseManager> dbManager;
    std::thread processorThread;

    std::atomic<bool> running;
    std::condition_variable cv;
    std::mutex cvMutex;

    void processNetworkDataThread(std::atomic<bool>& running,
        std::condition_variable& cv, DatabaseManager& dbManager);

};


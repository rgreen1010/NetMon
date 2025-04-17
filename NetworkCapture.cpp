

#include "NetMon.h"


/*
* 
*/
NetworkCapture::NetworkCapture(std::shared_ptr<DatabaseManager> dbManager)
    : dbManager(dbManager), pcapHandle(nullptr), running(false) {
}

NetworkCapture::~NetworkCapture() {
    stopCapture();
}

std::vector<std::string> NetworkCapture::getNetworkInterfaces() {
    std::vector<std::string> interfaces;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding network interfaces: " << errbuf << std::endl;
        return interfaces;
    }

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        interfaces.push_back(d->name);
    }

    pcap_freealldevs(alldevs);
    return interfaces;
}

bool NetworkCapture::setInterface(const std::string& name) {
    if (isCapturing()) {
        std::cerr << "Cannot change interface while capturing" << std::endl;
        return false;
    }

    interfaceName = name;
    return true;
}

bool NetworkCapture::startCapture() {
    if (isCapturing()) {
        std::cerr << "Capture already in progress" << std::endl;
        return false;
    }

    if (interfaceName.empty()) {
        std::cerr << "No interface selected" << std::endl;
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcapHandle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (pcapHandle == nullptr) {
        std::cerr << "Could not open device " << interfaceName << ": "
            << errbuf << std::endl;
        return false;
    }

    // Clear existing data
    {
        std::lock_guard<std::mutex> lock(trafficMutex);
        trafficData.clear();
    }

    running = true;
    captureThread = std::thread(&NetworkCapture::captureThreadFunction, this);

    return true;
}

void NetworkCapture::stopCapture() {
    if (!isCapturing()) {
        return;
    }

    running = false;

    if (captureThread.joinable()) {
        captureThread.join();
    }

    if (pcapHandle) {
        pcap_close(pcapHandle);
        pcapHandle = nullptr;
    }

    // When stopping, save data to database
    saveTrafficDataToDb();
}

bool NetworkCapture::isCapturing() const {
    return running;
}

std::map<ConversationKey, ConversationData> NetworkCapture::getCurrentTrafficData() {
    std::lock_guard<std::mutex> lock(trafficMutex);
    return trafficData;
}

void NetworkCapture::captureThreadFunction() {
    while (running) {
        struct pcap_pkthdr header;
        const u_char* packet = pcap_next(pcapHandle, &header);

        if (packet == nullptr) continue;

        // Process the packet
        processPacket(&header, packet);

        // Notify of updates if callback is set
        if (trafficUpdateCallback) {
            trafficUpdateCallback();
        }
    }
}

void NetworkCapture::processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    ConversationKey key;
    ConversationData data;

    if (extractConversationData(packet, key, data)) {
        std::lock_guard<std::mutex> lock(trafficMutex);

        if (trafficData.find(key) == trafficData.end()) {
            // New conversation
            data.packetCount = 1;
            data.byteCount = header->len;
            trafficData[key] = data;
        }
        else {
            // Existing conversation
            trafficData[key].packetCount++;
            trafficData[key].byteCount += header->len;
        }
    }
}

void NetworkCapture::saveTrafficDataToDb() {
    std::lock_guard<std::mutex> lock(trafficMutex);

    if (!trafficData.empty()) {
        dbManager->saveRawConversations(trafficData);
    }
}

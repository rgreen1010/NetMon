#pragma once

// Data structure for traffic information
struct ConversationData {
    int         id;         // needed for the database unused in the traffic map
    std::string sourceIp;
    std::string destIp;
    int         sourcePort;
    int         destPort;
    std::string protocol;
    long        packetCount;
    long        byteCount;
};

// Key for the map
struct ConversationKey {
    std::string sourceIp;
    std::string destIp;
    int sourcePort;
    int destPort;
    std::string protocol;

    bool operator<(const ConversationKey& other) const {
        if (sourceIp != other.sourceIp) return sourceIp < other.sourceIp;
        if (destIp != other.destIp) return destIp < other.destIp;
        if (sourcePort != other.sourcePort) return sourcePort < other.sourcePort;
        if (destPort != other.destPort) return destPort < other.destPort;
        return protocol < other.protocol;
    }
};


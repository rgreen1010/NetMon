/*
*/
#include "NetMon.h"
#include "DatabaseManager.h"


DatabaseManager::DatabaseManager(const std::string& dbPath) : db(nullptr) {
    int result = sqlite3_open(dbPath.c_str(), &db);
    if (result != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        db = nullptr;
    }

    // Enable foreign keys
    if (db) {
        executeQuery("PRAGMA foreign_keys = ON;");

        // Create indexes for better performance
        executeQuery("CREATE INDEX IF NOT EXISTS idx_raw_conv_source_ip ON raw_conversations(source_ip);");
        executeQuery("CREATE INDEX IF NOT EXISTS idx_raw_conv_dest_ip ON raw_conversations(dest_ip);");
        executeQuery("CREATE INDEX IF NOT EXISTS idx_conv_pairs_source_ip ON conversation_pairs(source_ip);");
        executeQuery("CREATE INDEX IF NOT EXISTS idx_conv_pairs_dest_ip ON conversation_pairs(dest_ip);");
    }
}

DatabaseManager::~DatabaseManager() {
    if (db) {
        sqlite3_close(db);
    }
}

bool DatabaseManager::initDatabase() {
    std::lock_guard<std::mutex> lock(dbMutex);

    const char* sql[] = {
        // Raw conversation table
        "CREATE TABLE IF NOT EXISTS raw_conversations ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "source_ip TEXT,"
        "dest_ip TEXT,"
        "source_port INTEGER,"
        "dest_port INTEGER,"
        "protocol TEXT,"
        "packet_count INTEGER,"
        "byte_count INTEGER,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");",

        // Conversation pair table
        "CREATE TABLE IF NOT EXISTS conversation_pairs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "source_ip TEXT,"
        "dest_ip TEXT,"
        "source_port INTEGER,"
        "dest_port INTEGER,"
        "protocol TEXT,"
        "packet_count INTEGER,"
        "byte_count INTEGER,"
        "first_seen DATETIME,"
        "last_seen DATETIME"
        ");",

        // Hostnames table
        "CREATE TABLE IF NOT EXISTS hostnames ("
        "ip TEXT PRIMARY KEY,"
        "hostname TEXT,"
        "last_updated DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");",

        // Whois table
        "CREATE TABLE IF NOT EXISTS whois_info ("
        "ip TEXT PRIMARY KEY,"
        "network_cidr TEXT,"
        "registrant TEXT,"
        "details TEXT,"
        "last_updated DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");"
    };

    for (const auto& query : sql) {
        if (!executeQuery(query)) {
            return false;
        }
    }

    return true;
}

bool DatabaseManager::saveRawConversation(const ConversationData& data) {
    std::lock_guard<std::mutex> lock(dbMutex);

    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO raw_conversations (source_ip, dest_ip, source_port, "
        "dest_port, protocol, packet_count, byte_count) VALUES (?, ?, ?, ?, ?, ?, ?)";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, data.sourceIp.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, data.destIp.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, data.sourcePort);
    sqlite3_bind_int(stmt, 4, data.destPort);
    sqlite3_bind_text(stmt, 5, data.protocol.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, data.packetCount);
    sqlite3_bind_int64(stmt, 7, data.byteCount);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    return success;
}

bool DatabaseManager::saveRawConversations(const std::map<ConversationKey, ConversationData>& trafficData) {
    std::lock_guard<std::mutex> lock(dbMutex);

    if (!beginTransaction()) {
        return false;
    }

    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO raw_conversations (source_ip, dest_ip, source_port, "
        "dest_port, protocol, packet_count, byte_count) VALUES (?, ?, ?, ?, ?, ?, ?)";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        rollbackTransaction();
        return false;
    }

    bool success = true;

    for (const auto& [key, data] : trafficData) {
        sqlite3_reset(stmt);

        sqlite3_bind_text(stmt, 1, data.sourceIp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, data.destIp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, data.sourcePort);
        sqlite3_bind_int(stmt, 4, data.destPort);
        sqlite3_bind_text(stmt, 5, data.protocol.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 6, data.packetCount);
        sqlite3_bind_int64(stmt, 7, data.byteCount);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "SQL error on insert: " << sqlite3_errmsg(db) << std::endl;
            success = false;
            break;
        }
    }

    sqlite3_finalize(stmt);

    if (success) {
        return commitTransaction();
    }
    else {
        rollbackTransaction();
        return false;
    }
}

std::vector<std::string> DatabaseManager::getUniqueIpAddresses(int limit) {
    std::lock_guard<std::mutex> lock(dbMutex);
    std::vector<std::string> ips;

    const char* sql = "SELECT DISTINCT source_ip FROM conversation_pairs "
        "UNION SELECT DISTINCT dest_ip FROM conversation_pairs";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return ips;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        ips.push_back(ip);
    }

    sqlite3_finalize(stmt);
    return ips;
}

bool DatabaseManager::executeQuery(const std::string& sql) {
    char* errMsg = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool DatabaseManager::beginTransaction() {
    return executeQuery("BEGIN TRANSACTION");
}

bool DatabaseManager::commitTransaction() {
    return executeQuery("COMMIT");
}

bool DatabaseManager::rollbackTransaction() {
    return executeQuery("ROLLBACK");
}



std::vector<ConversationData> DatabaseManager::getRawConversations() {
    std::lock_guard<std::mutex> lock(dbMutex);
    std::vector<ConversationData> result;

    const char* sql = "SELECT id, source_ip, dest_ip, source_port, dest_port, "
        "protocol, packet_count, byte_count FROM raw_conversations "
        "LIMIT 1000"; // Limit to avoid memory issues

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return result;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ConversationData data;
        // the data structure has no id field corresponding to the id from the database
        // is it needed?
        //data.id = sqlite3_column_int(stmt, 0);
        data.sourceIp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        data.destIp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        data.sourcePort = sqlite3_column_int(stmt, 3);
        data.destPort = sqlite3_column_int(stmt, 4);
        data.protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        data.packetCount = sqlite3_column_int64(stmt, 6);
        data.byteCount = sqlite3_column_int64(stmt, 7);

        result.push_back(data);
    }

    sqlite3_finalize(stmt);
    return result;
}

bool DatabaseManager::updateConversationPair(const std::string& sourceIp, const std::string& destIp,
    int sourcePort, int destPort, const std::string& protocol,
    long packetCount, long byteCount) {
    std::lock_guard<std::mutex> lock(dbMutex);

    // First check if the conversation pair exists
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, packet_count, byte_count FROM conversation_pairs "
        "WHERE source_ip = ? AND dest_ip = ? AND source_port = ? "
        "AND dest_port = ? AND protocol = ?";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, sourceIp.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, destIp.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, sourcePort);
    sqlite3_bind_int(stmt, 4, destPort);
    sqlite3_bind_text(stmt, 5, protocol.c_str(), -1, SQLITE_STATIC);

    bool success = false;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // Existing conversation - update
        int id = sqlite3_column_int(stmt, 0);
        long existingPackets = sqlite3_column_int64(stmt, 1);
        long existingBytes = sqlite3_column_int64(stmt, 2);

        sqlite3_finalize(stmt);

        // Update with new counts and timestamp
        const char* updateSql = "UPDATE conversation_pairs SET packet_count = ?, "
            "byte_count = ?, last_seen = CURRENT_TIMESTAMP "
            "WHERE id = ?";

        if (sqlite3_prepare_v2(db, updateSql, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }

        sqlite3_bind_int64(stmt, 1, existingPackets + packetCount);
        sqlite3_bind_int64(stmt, 2, existingBytes + byteCount);
        sqlite3_bind_int(stmt, 3, id);

        success = (sqlite3_step(stmt) == SQLITE_DONE);
    }
    else {
        // New conversation - insert
        sqlite3_finalize(stmt);

        const char* insertSql = "INSERT INTO conversation_pairs (source_ip, dest_ip, source_port, "
            "dest_port, protocol, packet_count, byte_count, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)";

        if (sqlite3_prepare_v2(db, insertSql, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }

        sqlite3_bind_text(stmt, 1, sourceIp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, destIp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, sourcePort);
        sqlite3_bind_int(stmt, 4, destPort);
        sqlite3_bind_text(stmt, 5, protocol.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 6, packetCount);
        sqlite3_bind_int64(stmt, 7, byteCount);

        success = (sqlite3_step(stmt) == SQLITE_DONE);
    }

    sqlite3_finalize(stmt);
    return success;
}

bool DatabaseManager::isHostnameUpToDate(const std::string& ip, int maxAgeDays) {
    std::lock_guard<std::mutex> lock(dbMutex);

    sqlite3_stmt* stmt;
    const char* sql = "SELECT 1 FROM hostnames WHERE ip = ? AND "
        "julianday('now') - julianday(last_updated) < ?";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, maxAgeDays);

    bool result = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return result;
}

std::vector<std::string> DatabaseManager::getIpsNeedingHostnameLookup(int maxAgeDays, int limit) {
    std::lock_guard<std::mutex> lock(dbMutex);
    std::vector<std::string> ips;

    // Get IPs that don't have hostname records or have outdated records
    const char* sql = "SELECT DISTINCT ip FROM ("
        "    SELECT source_ip as ip FROM conversation_pairs"
        "    UNION"
        "    SELECT dest_ip as ip FROM conversation_pairs"
        ") WHERE ip NOT IN ("
        "    SELECT ip FROM hostnames WHERE"
        "    julianday('now') - julianday(last_updated) < ?"
        ") LIMIT ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return ips;
    }

    sqlite3_bind_int(stmt, 1, maxAgeDays);
    sqlite3_bind_int(stmt, 2, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        ips.push_back(ip);
    }

    sqlite3_finalize(stmt);
    return ips;
}


/*
* 
*/
std::vector<std::pair<std::string, long>> DatabaseManager::getTopSourceIps(int limit) {
    std::lock_guard<std::mutex> lock(dbMutex);
    std::vector<std::pair<std::string, long>> result;

    const char* sql = "SELECT source_ip, SUM(packet_count) as total_packets "
        "FROM conversation_pairs GROUP BY source_ip "
        "ORDER BY total_packets DESC LIMIT ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return result;
    }

    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        long packets = sqlite3_column_int64(stmt, 1);
        result.push_back({ ip, packets });
    }

    sqlite3_finalize(stmt);
    return result;
}

//----------------------------PLACE HOLDER WHOIS METHODS -------------------------------
// Whois database entries access methods use "new" WhoisService data structures
bool updateWhoisInfo(const std::string& ip, const WhoisInfo& info) {
    //Placeholder
    return true;
};

bool isWhoisInfoUpToDate(const std::string& ip, int maxAgeDays = 30) {
    //Placeholder
    return true;
};

WhoisInfo getWhoisInfo(const std::string& ip) {
    //Placeholder
    WhoisInfo info;
    return info;
};
std::vector<std::string> getIpsNeedingWhoisLookup(int maxAgeDays = 30, int limit = 50) {
    //Placeholder -- How do I create a vector of dummy ip addresses?
    std::vector<std::string> ipList;
    return ipList;
};

#include "NetMon.h"

//NetMon::NetMon(QWidget *parent)
//    : QMainWindow(parent)
//{
//    ui.setupUi(this);
//}
//
//NetMon::~NetMon()
//{}


class NetMonApp : public QMainWindow {
    Q_OBJECT

public:
    NetMonApp(QWidget* parent = nullptr);
    ~NetMonApp();

private slots:
    void startCapture();
    void stopCapture();
    void updateTrafficDisplay();
    void triggerHostnameUpdate();
    void triggerWhoisUpdate();
    void exportToCsv();
    void about();
    void setupMenus();

private:
    void setupTrafficTable();
    void populateNetworkInterfaces();
    void createStatusBar();

    // UI elements
    QComboBox* interfaceCombo;
    QPushButton* startButton;
    QPushButton* stopButton;
    QPushButton* updateHostnamesButton;
    QPushButton* updateWhoisButton;
    QTableWidget* trafficTable;
    QTimer* updateTimer;
    QStatusBar* statusBar;
    QLabel* statusLabel;
    QLabel* packetCountLabel;

    // Thread management
    std::thread producer;
    std::thread consumer;
    std::atomic<bool> running{ false };
    std::condition_variable cv;
    std::mutex cvMutex;

    // Shared data
    std::map<ConversationKey, ConversationData> trafficData;
    std::mutex trafficMutex;

    // Database
    DatabaseManager dbManager;

    // Stats
    long totalPackets = 0;
};

// ************************************************************* (())

// Implementation

NetMonApp::NetMonApp(QWidget* parent) : QMainWindow(parent), dbManager("network_monitor.db") {
    setWindowTitle("Network Traffic Monitor");
    resize(900, 700);

    // Initialize database
    if (!dbManager.initDatabase()) {
        QMessageBox::critical(this, "Database Error", "Failed to initialize database schema");
    }

    // Create central widget and layout
    QWidget* centralWidget = new QWidget(this);
    QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);

    // Controls layout
    QHBoxLayout* controlsLayout = new QHBoxLayout();

    // Interface selection
    QLabel* interfaceLabel = new QLabel("Network Interface:", this);
    interfaceCombo = new QComboBox(this);
    populateNetworkInterfaces();

    // Start/Stop buttons
    startButton = new QPushButton("Start Capture", this);
    stopButton = new QPushButton("Stop Capture", this);
    stopButton->setEnabled(false);

    // Add controls to layout
    controlsLayout->addWidget(interfaceLabel);
    controlsLayout->addWidget(interfaceCombo);
    controlsLayout->addWidget(startButton);
    controlsLayout->addWidget(stopButton);
    controlsLayout->addStretch();

    // Data update buttons
    QHBoxLayout* updateButtonsLayout = new QHBoxLayout();

    updateHostnamesButton = new QPushButton("Update Hostnames", this);
    updateWhoisButton = new QPushButton("Update WHOIS", this);

    updateButtonsLayout->addWidget(updateHostnamesButton);
    updateButtonsLayout->addWidget(updateWhoisButton);
    updateButtonsLayout->addStretch();

    // Traffic data table
    trafficTable = new QTableWidget(this);
    setupTrafficTable();

    // Add all widgets to main layout
    mainLayout->addLayout(controlsLayout);
    mainLayout->addLayout(updateButtonsLayout);
    mainLayout->addWidget(trafficTable);

    setCentralWidget(centralWidget);

    // Setup menus
    setupMenus();

    // Create status bar
    createStatusBar();

    // Connect signals and slots
    connect(startButton, &QPushButton::clicked, this, &NetMonApp::startCapture);
    connect(stopButton, &QPushButton::clicked, this, &NetMonApp::stopCapture);
    connect(updateHostnamesButton, &QPushButton::clicked, this, &NetMonApp::triggerHostnameUpdate);
    connect(updateWhoisButton, &QPushButton::clicked, this, &NetMonApp::triggerWhoisUpdate);

    // Setup timer for periodic updates
    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &NetMonApp::updateTrafficDisplay);
    updateTimer->start(1000); // Update every second
}

NetMonApp::~NetMonApp() {
    // Ensure threads are stopped
    if (running) {
        stopCapture();
    }
}

void NetMonApp::setupMenus() {
    QMenu* fileMenu = menuBar()->addMenu("&File");

    QAction* exportAction = new QAction("&Export to CSV", this);
    connect(exportAction, &QAction::triggered, this, &NetMonApp::exportToCsv);
    fileMenu->addAction(exportAction);

    fileMenu->addSeparator();

    QAction* exitAction = new QAction("E&xit", this);
    connect(exitAction, &QAction::triggered, this, &QWidget::close);
    fileMenu->addAction(exitAction);

    QMenu* helpMenu = menuBar()->addMenu("&Help");

    QAction* aboutAction = new QAction("&About", this);
    connect(aboutAction, &QAction::triggered, this, &NetMonApp::about);
    helpMenu->addAction(aboutAction);
}

void NetMonApp::createStatusBar() {
    statusBar = new QStatusBar(this);
    setStatusBar(statusBar);

    statusLabel = new QLabel("Ready", this);
    statusBar->addWidget(statusLabel);

    packetCountLabel = new QLabel("Packets: 0", this);
    statusBar->addPermanentWidget(packetCountLabel);
}

void NetMonApp::setupTrafficTable() {
    // Set columns
    QStringList headers = { "Source IP", "Source Host", "Dest IP", "Dest Host", "Source Port",
                           "Dest Port", "Protocol", "Packet Count", "Byte Count" };
    trafficTable->setColumnCount(headers.size());
    trafficTable->setHorizontalHeaderLabels(headers);
    trafficTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    trafficTable->setEditTriggers(QTableWidget::NoEditTriggers);
    trafficTable->setSortingEnabled(true);
    trafficTable->setSelectionBehavior(QTableWidget::SelectRows);
    trafficTable->setAlternatingRowColors(true);
}

void NetMonApp::populateNetworkInterfaces() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        QMessageBox::critical(this, "Error",
            QString("Failed to get network interfaces: %1").arg(errbuf));
        return;
    }

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        QString description = d->description ? d->description : "No description available";
        interfaceCombo->addItem(QString("%1 (%2)").arg(d->name).arg(description), QVariant(d->name ));
    }

    pcap_freealldevs(alldevs);
}

void NetMonApp::startCapture() {
    if (interfaceCombo->currentIndex() < 0) {
        QMessageBox::warning(this, "Error", "Please select a network interface");
        return;
    }

    std::string selectedInterface = interfaceCombo->currentData().toString().toStdString();

    // Clear existing data
    {
        std::lock_guard<std::mutex> lock(trafficMutex);
        trafficData.clear();
        totalPackets = 0;
    }

    // Set running flag to true
    running = true;

    // Start producer thread
    producer = std::thread([this, selectedInterface]() {
        producerThread(trafficData, trafficMutex, running, selectedInterface, totalPackets, dbManager);
        });

    // Start consumer thread
    consumer = std::thread([this]() {
        consumerThread(running, cv, dbManager);
        });

    // Update UI
    startButton->setEnabled(false);
    stopButton->setEnabled(true);
    interfaceCombo->setEnabled(false);
    statusLabel->setText("Capturing...");
}

void NetMonApp::stopCapture() {
    if (!running) return;

    // Set running flag to false
    running = false;

    // Notify consumer thread
    cv.notify_one();

    // Update status
    statusLabel->setText("Stopping capture...");
    QApplication::processEvents();

    // Wait for threads to finish
    if (producer.joinable()) producer.join();
    if (consumer.joinable()) consumer.join();

    // Update UI
    startButton->setEnabled(true);
    stopButton->setEnabled(false);
    interfaceCombo->setEnabled(true);
    statusLabel->setText("Ready");

    // Final update of traffic display
    updateTrafficDisplay();

    // Save all traffic data to database
    std::lock_guard<std::mutex> lock(trafficMutex);
    dbManager.saveRawConversations(trafficData);
}

void NetMonApp::updateTrafficDisplay() {
    std::lock_guard<std::mutex> lock(trafficMutex);

    // Update table with current traffic data
    trafficTable->setRowCount(trafficData.size());

    int row = 0;
    for (const auto& [key, data] : trafficData) {
        std::string sourceHost = dbManager.getHostname(data.sourceIp);
        std::string destHost = dbManager.getHostname(data.destIp);

        trafficTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(data.sourceIp)));
        trafficTable->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(sourceHost)));
        trafficTable->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(data.destIp)));
        trafficTable->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(destHost)));
        trafficTable->setItem(row, 4, new QTableWidgetItem(QString::number(data.sourcePort)));
        trafficTable->setItem(row, 5, new QTableWidgetItem(QString::number(data.destPort)));
        trafficTable->setItem(row, 6, new QTableWidgetItem(QString::fromStdString(data.protocol)));
        trafficTable->setItem(row, 7, new QTableWidgetItem(QString::number(data.packetCount)));
        trafficTable->setItem(row, 8, new QTableWidgetItem(QString::number(data.byteCount)));
        row++;
    }

    // Update packet count in status bar
    packetCountLabel->setText(QString("Packets: %1").arg(totalPackets));
}

void NetMonApp::triggerHostnameUpdate() {
    statusLabel->setText("Updating hostnames...");

    // Create a separate thread for hostname updates
    std::thread hostnameThread([this]() {
        auto ips = dbManager.getIpsNeedingHostnameLookup();

        for (const auto& ip : ips) {
            statusLabel->setText(QString("Resolving hostname for %1...").arg(QString::fromStdString(ip)));
            QApplication::processEvents();

            std::string hostname = performDnsLookup(ip);
            if (hostname.empty()) {
                hostname = performLocalLookup(ip);
            }

            if (!hostname.empty()) {
                dbManager.updateHostname(ip, hostname);
            }
        }

        statusLabel->setText("Hostname update complete");
        // Update display to show hostnames
        updateTrafficDisplay();
        });

    hostnameThread.detach();
}

void NetMonApp::triggerWhoisUpdate() {

    statusLabel->setText("Updating WHOIS information...");

    // Create a separate thread for WHOIS updates
    std::thread whoisThread([this]() {
        WhoisService whoisService;
        auto ips = dbManager.getIpsNeedingWhoisLookup();

        for (const auto& ip : ips) {
            statusLabel->setText(QString("Looking up WHOIS for %1...").arg(QString::fromStdString(ip)));
            QApplication::processEvents();

            WhoisService::WhoisInfo info = whoisService.lookup(ip);
            if (!info.registrant.empty()) {
                //dbManager.updateWhoisInfo(ip, info.networkCidr, info.registrant, info.details);
                dbManager.updateWhoisInfo(ip, info);

            }
        }

        statusLabel->setText("WHOIS update complete");
        });

    whoisThread.detach();
}

void NetMonApp::exportToCsv() {
    QString fileName = QFileDialog::getSaveFileName(this, "Export Traffic Data",
        QDir::homePath(), "CSV Files (*.csv)");
    if (fileName.isEmpty()) {
        return;
    }

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open file for writing");
        return;
    }

    QTextStream out(&file);

    // Write header
    out << "Source IP,Source Host,Dest IP,Dest Host,Source Port,Dest Port,Protocol,Packet Count,Byte Count\n";

    // Write data rows
    std::lock_guard<std::mutex> lock(trafficMutex);
    for (const auto& [key, data] : trafficData) {
        std::string sourceHost = dbManager.getHostname(data.sourceIp);
        std::string destHost = dbManager.getHostname(data.destIp);

        out << QString::fromStdString(data.sourceIp) << ","
            << QString::fromStdString(sourceHost) << ","
            << QString::fromStdString(data.destIp) << ","
            << QString::fromStdString(destHost) << ","
            << data.sourcePort << ","
            << data.destPort << ","
            << QString::fromStdString(data.protocol) << ","
            << data.packetCount << ","
            << data.byteCount << "\n";
    }

    file.close();
    statusLabel->setText("Data exported to " + fileName);
}

void NetMonApp::about() {
    QMessageBox::about(this, "About Network Traffic Monitor",
        "Network Traffic Monitor v1.0\n\n"
        "A tool to monitor network traffic, collect conversation information, "
        "and analyze network data.\n\n"
        "Uses npcap for packet capture, SQLite for data storage, and Qt for the user interface.");
}

// External thread functions - these are defined elsewhere but referenced here

// Producer thread processes network packets
extern void producerThread(std::map<ConversationKey, ConversationData>& trafficData,
    std::mutex& trafficMutex,
    std::atomic<bool>& running,
    const std::string& interfaceName,
    long& totalPackets,
    DatabaseManager& dbManager);

// Consumer thread processes database operations
extern void consumerThread(std::atomic<bool>& running,
    std::condition_variable& cv,
    DatabaseManager& dbManager);

// Utility functions for hostname and WHOIS lookups
extern std::string performDnsLookup(const std::string& ip);
extern std::string performLocalLookup(const std::string& ip);
extern WhoisInfo performWhoisLookup(const std::string& ip);
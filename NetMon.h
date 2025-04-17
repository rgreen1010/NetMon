#pragma once

#include <iostream>
#include <map>
#include <string>
#include <sqlite3.h>
#include <pcap.h>

#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QStatusBar>
#include <QtCore/QTimer>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QWidgetAction>
#include <QFileDialog>
#include <QVariant>
#include <sstream>

#include "ui_NetMon.h"
#include "NetworkCapture.h"
#include "DatabaseManager.h"
#include "DataProcessor.h"
#include "WhoisService.h"
#include "ConversationData.h"




/*
class NetMon : public QMainWindow
{
    Q_OBJECT

    public:
        NetMon(QWidget *parent = nullptr);
        ~NetMon();

    private:
        Ui::NetMonClass ui;
};
*/
/*
*******************************************************************
*/
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
    void showStatistics();

private:
    // UI elements
    QComboBox* interfaceCombo;
    QPushButton* startButton;
    QPushButton* stopButton;
    QPushButton* updateHostnamesButton;
    QPushButton* updateWhoisButton;
    QPushButton* statisticsButton;
    QTableWidget* trafficTable;
    QTimer* updateTimer;

    // Core components
    std::shared_ptr<DatabaseManager> dbManager;
    std::unique_ptr<NetworkCapture> networkCapture;
    std::unique_ptr<DataProcessor> dataProcessor;

    // Setup methods
    void setupUi();
    void setupTrafficTable();
    void populateNetworkInterfaces();
    void connectSignals();
};
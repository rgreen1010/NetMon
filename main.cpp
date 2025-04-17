#include "NetMon.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    NetMon w;
    w.show();
    return a.exec();
}

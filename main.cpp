#include "NetMon.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    NetMonApp w;
    w.show();
    return a.exec();
}

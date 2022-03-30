#include "network_sniff.h"
#include <QtWidgets/QApplication>
#include<QVector>
#include<memory>
#include "pcap.h"
#include<ws2tcpip.h>
#include<winsock2.h>
int main(int argc, char *argv[])
{   
    
    QApplication a(argc, argv);
    network_sniff w;
    w.ini();
    w.show();
    return a.exec();
}

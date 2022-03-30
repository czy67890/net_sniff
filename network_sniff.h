#pragma once
#include"work_thread.h"
#include <QtWidgets/QMainWindow>
#include<QVector>
#include<memory>
#include<ws2tcpip.h>
#include<winsock2.h>
#include<QList>
#include<QStandardItemModel>
#include<QListView>
#include<QStringListModel>
#include"data_struct.h"
#include "ui_network_sniff.h"
#include"filter_dialog.h"
#include"count.h"
class network_sniff : public QMainWindow
{
    Q_OBJECT

public:
    QString selected_filter = "ALL";
    network_sniff(QWidget *parent = Q_NULLPTR);
    //ѡ��������±�
    int select_index;
    //������Ϣ
    char err_buf[PCAP_ERRBUF_SIZE];
    //ѡ��Ĺ���������
    int select_f_index;
    //�豸ָ��
    pcap_if_t* all_device;
    pcap_if_t* now_device;
    pcap_t* adhandle;
    //���������������
    u_int netmask;
    struct bpf_program hcode;
    //ͷ���ļ�
    struct pcap_pkthdr* header;
    //������
    const u_char* pkt_data;
    //�������ݰ�������
    int pkt_count[8] = { 0 };
    QVector<QStringList> pkt_vector;
    //ԭʼpacket����
    QVector<QString> raw_pkt_data;
    bool is_stop;
    WorkThread* work_thread = nullptr;
    void get_dev_list(QVector<DevInfo> &dev_list);
    void ini();
    void ui_after_start();
    void ui_after_stop();
    void show_pkt_detail();
    void show_pkt_bin();
    void add_menu(const QPoint& pos);
private:
    Ui::network_sniffClass ui;
    bool filter_http = false;
    signals:
    void start();
    void stop();
public slots:
    QString recv_filter_rule();
    void Start();
    void Stop();
    void add_to_view(QStringList data,int row_index);
};

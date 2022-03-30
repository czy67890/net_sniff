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
    //选择的网卡下标
    int select_index;
    //错误信息
    char err_buf[PCAP_ERRBUF_SIZE];
    //选择的过滤器设置
    int select_f_index;
    //设备指针
    pcap_if_t* all_device;
    pcap_if_t* now_device;
    pcap_t* adhandle;
    //网络掩码与过滤器
    u_int netmask;
    struct bpf_program hcode;
    //头部文件
    struct pcap_pkthdr* header;
    //包数据
    const u_char* pkt_data;
    //各种数据包的数量
    int pkt_count[8] = { 0 };
    QVector<QStringList> pkt_vector;
    //原始packet数据
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

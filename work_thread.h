#pragma once
#include<QThread>
#include<QMainWindow>
#include<QVector>
#include"data_struct.h"
#include"pcap.h"
#include<ws2tcpip.h>
#include<winsock2.h>
class WorkThread :public QThread{
	Q_OBJECT;
public:
	//直接由构造函数从main来继承
	pcap_if_t* all_device;
	QMainWindow* w;
	int select_index;
	QString select_filter;
	pcap_if_t* now_device;
	QVector<QStringList>* pkt_vector;
	QVector<QString>* raw_pkt_data;
	//内部使用的变量
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t* adhandle;
    //网络掩码与过滤器
    u_int netmask;
	//设置格式过滤
    struct bpf_program hcode;
    //头部文件
    struct pcap_pkthdr* header;
    //包数据
    const u_char* pkt_data;
    //各种数据包的数量
	int* pkt_count;
	bool stop_thread = false;
	bool filter_http = false;
	bool is_trace = false;
	WorkThread(QMainWindow* w, pcap_if_t* all_device, int select_index, QString selecte_filter,QVector<QStringList> * pkt_vector,
		QVector<QString> * raw_pkt_data,int *pkt_count,bool filter_http,bool is_trace = false);
	~WorkThread();
	//运行捕获包的线程
	void run();
	bool check_eth(); 
	u_int get_net_mask();
	void start_cap();

	bool set_filter(QString rule);
public: signals:
	void send_to_main(QStringList data_send, int row_index);
};
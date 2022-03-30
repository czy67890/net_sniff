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
	//ֱ���ɹ��캯����main���̳�
	pcap_if_t* all_device;
	QMainWindow* w;
	int select_index;
	QString select_filter;
	pcap_if_t* now_device;
	QVector<QStringList>* pkt_vector;
	QVector<QString>* raw_pkt_data;
	//�ڲ�ʹ�õı���
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t* adhandle;
    //���������������
    u_int netmask;
	//���ø�ʽ����
    struct bpf_program hcode;
    //ͷ���ļ�
    struct pcap_pkthdr* header;
    //������
    const u_char* pkt_data;
    //�������ݰ�������
	int* pkt_count;
	bool stop_thread = false;
	bool filter_http = false;
	bool is_trace = false;
	WorkThread(QMainWindow* w, pcap_if_t* all_device, int select_index, QString selecte_filter,QVector<QStringList> * pkt_vector,
		QVector<QString> * raw_pkt_data,int *pkt_count,bool filter_http,bool is_trace = false);
	~WorkThread();
	//���в�������߳�
	void run();
	bool check_eth(); 
	u_int get_net_mask();
	void start_cap();

	bool set_filter(QString rule);
public: signals:
	void send_to_main(QStringList data_send, int row_index);
};
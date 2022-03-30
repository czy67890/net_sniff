#pragma once
#include<QString>
#include<QVector>
#include<pcap.h>
const static int IPV4 = 0;
const static int IPV6 = 1;
const static int ARP = 2;
const static int TCP = 3;
const static int UDP = 4;
const static int ICMP = 5;
const static int HTTP = 6;
const static int OTHER = 7;
const static int MAX_URL_LEN = 2083;
struct DevInfo {
	QString name = "";
	QString description = "";
};
struct EthHeader {
	u_char src_addr[6];
	u_char dest_addr[6];
	u_short type;
};
struct IpHeader {
	u_char ver_ihl;//�汾+ͷ������
	u_char tos;//���ַ���
	u_short tlen;//�ܳ���
	u_short identification;//��ʶ
	u_short flag_dev;//��־+Ƭƫ��
	u_char ttl;//����ʱ��
	u_char protocal;//Э��
	u_short crc;//�ײ�У���
	u_char src_addr[4];//Դ��ַ
	u_char dest_addr[4];//Ŀ�ĵ�ַ
	u_int op_pad;//ѡ���ֶ�
};
struct Ipv6Header {
	u_int version :4
	, flowtype : 8
	, flowid : 20;
	u_short plen;
	u_char nh;
	u_char hlim;
	u_short src_addr[8];
	u_short dest_addr[8];
};
struct ArpHeader {
	u_short ar_hw;
	u_short ar_port;
	u_char ar_hln;
	u_char ar_pln;
	u_short ar_op;
	u_char ar_srcmac[6];
	u_char ar_srcip[4];
	u_char ar_destmac[6];
	u_char ar_destip[4];
};
struct TcpHeader {
	u_short src_port;//Դ��
	u_short dest_port;//Ŀ�Ķ�
	u_int seq;//seq���
	u_int ack;//ack���
	u_short hl_flag;//�ֶ�
	u_short windows_size;//���ڴ�С
	u_short check_sum;//У���
	//differ from the source code
	u_short urg_pointer;//����ָ��
	u_int ops;//ѡ��
};
struct UdpHeader {
	u_short src_port;
	u_short dest_port;
	u_short udp_len;
	u_short check_sum;
	u_int data;
};
struct IcmpHeader {
	u_char type;
	u_char code;
	u_short check_sum;
	u_short id;
	u_short seq;
};
struct PktData {
	int len;
	const u_char* pkt_data;
};
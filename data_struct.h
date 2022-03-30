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
	u_char ver_ihl;//版本+头部长度
	u_char tos;//区分服务
	u_short tlen;//总长度
	u_short identification;//标识
	u_short flag_dev;//标志+片偏移
	u_char ttl;//生存时间
	u_char protocal;//协议
	u_short crc;//首部校验和
	u_char src_addr[4];//源地址
	u_char dest_addr[4];//目的地址
	u_int op_pad;//选项字段
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
	u_short src_port;//源端
	u_short dest_port;//目的端
	u_int seq;//seq编号
	u_int ack;//ack编号
	u_short hl_flag;//字段
	u_short windows_size;//窗口大小
	u_short check_sum;//校验和
	//differ from the source code
	u_short urg_pointer;//紧急指针
	u_int ops;//选项
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
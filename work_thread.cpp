#include"work_thread.h"
#include<string.h>
#include<stdlib.h>
#include<stdint.h>
#include<stdio.h>
WorkThread::WorkThread(QMainWindow* w, pcap_if_t* all_device, int select_index, QString selecte_filter, QVector<QStringList>* pkt_vector,QVector<QString>* raw_pkt_data,int *pkt_count
	,bool filter_http,bool is_trace)
{
	this->w = w;
	this->all_device = all_device;
	this->select_index = select_index;
	this->select_filter = selecte_filter;
	this->pkt_vector = pkt_vector;
	this->raw_pkt_data = raw_pkt_data;
	this->pkt_count = pkt_count;
	this->filter_http = filter_http;
	this->is_trace = true;
}

WorkThread::~WorkThread()
{	
	//关闭网卡设备
	pcap_close(adhandle);
	//线程安全的关闭该线程
	requestInterruption();
	quit();
	wait();
}
void WorkThread::run()
{
	stop_thread = false;
	now_device = all_device;
	for (int i = 0; i < select_index; ++i) {
		now_device = now_device->next;
	}
	//TODO;;绑定一个信号触发到主线程的详细信息显示
	if ((adhandle = pcap_open_live(now_device->name, 65536, 1, 1000, err_buf)) == NULL) {
		
	}
	//TODO::绑定信号到主线程详细显示错误信息
	if (check_eth() == false) {
		
	}
	netmask = get_net_mask();
	if (!set_filter(select_filter)) {
		return;
	}
	else {
		//开始抓包
		start_cap();
	}
}

bool WorkThread::check_eth()
{	
	//若不是以太网则返回
	if (pcap_datalink(this->adhandle) != DLT_EN10MB) {
		return false;
	}
	return true;
}
u_int WorkThread::get_net_mask()
{	
	u_int netmask;
	if (now_device->addresses != NULL) {
		netmask = ((struct sockaddr_in*)(now_device->addresses->netmask))->sin_addr.S_un.S_addr;

	}
	else {
		netmask = 0xffffff;
	}
	return netmask;
}
void WorkThread::start_cap()
{
	int res;
	int row_index = 0;
	//pcap_next_ex::从接口不断获取报文
	while((res = pcap_next_ex(adhandle,&header,&pkt_data))>= 0 ){
		if (res == 0) {
			continue;
		}
		//存储接受数据
		//data格式 col_name << "时间" << "包长" << "源地址" << "目的地址" << "协议" << "源端口" << "目的端口";
 		QString data[7];
		QStringList data_info;
		//转换为本地时间 时区:+8
		struct tm local_time;
		char timestr[20];
		EthHeader* eh = (EthHeader*)pkt_data;
		QString tmp = "";
		char macStr[8];
		snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
			eh->src_addr[0], eh->src_addr[1], eh->src_addr[2], eh->src_addr[3], eh->src_addr[4], eh->src_addr[5]);

		QString src_mac = QString(macStr);
		data_info << src_mac;
		snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
			eh->dest_addr[0], eh->dest_addr[1], eh->dest_addr[2], eh->dest_addr[3], eh->dest_addr[4], eh->dest_addr[5]);
		;
		QString dest_mac = QString(macStr);
		data_info << dest_mac;
		IpHeader* ip_h;
		Ipv6Header* ipv6_h;
		ArpHeader* arp_h;
		TcpHeader* tcp_h;
		UdpHeader* udp_h;
		IcmpHeader* icmp_h;
		//接下来判断接受到的包的数据类型
		u_short src_port;
		u_short dest_port;
		//获得该包的time
		time_t local_tv_sec = header->ts.tv_sec;
		//设置到local_time
		localtime_s(&local_time,&local_tv_sec);
		//将时间格式化
		strftime(timestr,sizeof(timestr),"%H:%M:%S",&local_time);
		//设置时间
		data[0] = QString(timestr);
		//设置包长
		data[1] = QString::number(header->len);
		//跳过链路层的包头长度14字节
		ip_h = (IpHeader*)(pkt_data + 14);
		ipv6_h = (Ipv6Header*)(pkt_data + 14);
		arp_h = (ArpHeader*)(pkt_data + 14);
		//转换为主机字节序列后判断类型
		int n_type = ntohs(eh->type);
		//IPV4的情况
		if (n_type == 2048) {
			pkt_count[0]++;
			data_info << "IPV4";
			data[4] = "IPV4";
			data[2] = QString::number(ip_h->src_addr[0]) +"." +
				QString::number(ip_h->src_addr[1]) + "." +
				QString::number(ip_h->src_addr[2]) + "." +
				QString::number(ip_h->src_addr[3]);
			data[3] = QString::number(ip_h->dest_addr[0]) + "." +
				QString::number(ip_h->dest_addr[1]) + "." +
				QString::number(ip_h->dest_addr[2]) + "." +
				QString::number(ip_h->dest_addr[3]);
			//获得头部长度
			u_int iph_len = (ip_h->ver_ihl & 0xf) << 2;
			//将ipv4格式存入data_info中
			data_info<<(QString::number(iph_len));
			data_info<<(QString::number(ip_h->tos));
			data_info<<(QString::number(ip_h->tlen));
			data_info<<(QString::number(ip_h->identification));
			data_info<<(QString::number(ip_h->flag_dev&0xe000));
			data_info<<(QString::number(ip_h->flag_dev & 0x1fff));
			data_info<<(QString::number(ip_h->ttl));
			//设置UDP和TCP与ICMP的头部起始位置
			udp_h = (UdpHeader*)(pkt_data + 14 + iph_len);
			tcp_h = (TcpHeader*)(pkt_data + 14 + iph_len);
			icmp_h = (IcmpHeader*)(pkt_data + 14 + iph_len);
			//TCP报文的情况
			if (ip_h->protocal == 6) {
				u_int tcp_header_len = 0;
				pkt_count[3]++;
				data_info << "TCP";
				data[4] = "TCP";
				data_info<<(QString::number(ip_h->crc));
				data_info<<(data[2]);
				data_info<<(data[3]);
				data_info<<(QString::number(ip_h->op_pad));
				src_port = ntohs(tcp_h->src_port);
				dest_port = ntohs(tcp_h->dest_port);
				//填充源端与目的端
				data[5] = QString::number(src_port);
				data[6] = QString::number(dest_port);
				data_info<<(data[5]);
				data_info<<(data[6]);
				tcp_header_len = ntohs(tcp_h->hl_flag);
				tcp_header_len = tcp_header_len & 0xf000;
				tcp_header_len >>= 10;
				data_info<<(QString::number(ntohs(tcp_h->seq)));
				data_info<<(QString::number(ntohs(tcp_h->ack)));
				data_info << (QString::number(tcp_header_len));//tcp首部长度
				data_info<<(QString::number(ntohs(tcp_h->hl_flag)&0x0020>>5));
				data_info<<(QString::number(ntohs(tcp_h->hl_flag)&0x0010>>4));
				data_info<<(QString::number(ntohs(tcp_h->hl_flag)&0x0008>>3));
				data_info<<(QString::number(ntohs(tcp_h->hl_flag) & 0x0004>>2));
				data_info<<(QString::number(ntohs(tcp_h->hl_flag )& 0x0002>>1));
				data_info<<(QString::number(ntohs(tcp_h->hl_flag) & 0x0001));
				data_info<<(QString::number(ntohs(tcp_h->windows_size)));
				data_info<<(QString::number(ntohs(tcp_h->check_sum)));
				data_info<<(QString::number(ntohs(tcp_h->urg_pointer)));
				data_info<<(QString::number(tcp_h->ops));
				u_char* http_ana = (u_char*)(pkt_data + 14 + iph_len + tcp_header_len);
				std::string temp_s = "";
				int count = 14 + iph_len + tcp_header_len;
				if (((strstr((char*)http_ana, "POST")) != NULL) || (strstr((char*)http_ana, "GET")) != NULL) {
					data[4] = "HTTP";
					pkt_count[HTTP]++;
					data_info << "HTTP";
					while (count< header->caplen) {
						temp_s.push_back(*http_ana);
						http_ana++;
						count++;
					}
					data_info << QString::fromStdString(temp_s);
				}
			}
			//UDP的情况
			else if (ip_h->protocal == 17) {
				pkt_count[4]++;
				data_info << "UDP";
				data[4] = "UDP";
				data_info<<(QString::number(ip_h->crc));
				data_info<<(data[2]);
				data_info<<(data[3]);
				data_info<<(QString::number(ip_h->op_pad));
				src_port = ntohs(udp_h->src_port);
				dest_port = ntohs(udp_h->dest_port);
				//填充源端与目的端
				data[5] = QString::number(src_port);
				data[6] = QString::number(dest_port);
				data_info<<(data[5]);
				data_info<<(data[6]);
				data_info<<(QString::number(udp_h->udp_len));
				data_info<<(QString::number(tcp_h->check_sum));
				data_info<<(QString::number(udp_h->data));
			}
			//ICMP协议的情况
			else if (ip_h->protocal == 1) {
				pkt_count[5]++;
				data[4] = "ICMP";
				data_info << "ICMP";
				data_info<<(data[2]);
				data_info<<(data[3]);
				data_info<<(QString::number(ip_h->op_pad));
				data[5] = data[6] = "---";
				data_info<<(QString::number(icmp_h->type));
				data_info<<(QString::number(icmp_h->code));
				data_info<<(QString::number(icmp_h->check_sum));
				data_info<<(QString::number(icmp_h->id));
				data_info<<(QString::number(icmp_h->seq));
			}
			else {
				pkt_count[OTHER]++;
				data_info << "OTHER";
				data_info << (QString::number(ip_h->crc));
				data_info << (data[2]);
				data_info << (data[3]);
				data_info << (QString::number(ip_h->op_pad));
				data[5] = data[6] = "OTHER";
			}
		}
		//IPV6的情况
		else if (n_type == 34525) {
			pkt_count[IPV6]++;
			data[4] = "IPV6";
			data_info << "IPV6";
			data_info<<(QString::number(ipv6_h->flowtype));
			data_info<<(QString::number(ipv6_h->flowid));
			data_info<<(QString::number(ipv6_h->plen));
			QString temp = "";
			for (int i = 0; i < 8; ++i) {
				temp = temp+ QString::number(ipv6_h->src_addr[i]);
				if(i != 7)
				temp += ":";
			}
			data[2] = temp;
			temp.clear();
			for (int i = 0; i < 8; ++i) {
				temp = temp + QString::number(ipv6_h->dest_addr[i]);
				if (i != 7)
					temp += ":";
			}
			data[3] = temp;
			u_int ipv6_len = ipv6_h->plen;
			icmp_h = (IcmpHeader*)(pkt_data + ipv6_len);
			udp_h = (UdpHeader*)(pkt_data + ipv6_len);
			tcp_h = (TcpHeader*)(pkt_data + ipv6_len);
			if (ipv6_h->nh == 6) {
				u_int tcp_header_len = 0;
				pkt_count[TCP]++;
				data_info << "TCP";
				data[4] = "TCP";
				data_info<<(QString::number(ipv6_h->hlim));
				data_info<<(data[2]);
				data_info<<(data[3]);
				src_port = ntohs(tcp_h->src_port);
				dest_port = ntohs(tcp_h->dest_port);
				//填充源端与目的端
				data[5] = QString::number(src_port);
				data[6] = QString::number(dest_port);
				data_info<<(data[5]);
				data_info<<(data[6]);
				tcp_header_len = ntohs(tcp_h->hl_flag);
				tcp_header_len = tcp_header_len & 0xf000;
				tcp_header_len >>= 10;
				data_info << (QString::number(ntohs(tcp_h->seq)));
				data_info << (QString::number(ntohs(tcp_h->ack)));
				data_info << QString::number(tcp_header_len);//tcp首部长度
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0020 >> 5));
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0010 >> 4));
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0008 >> 3));
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0004 >> 2));
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0002 >> 1));
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0001));
				data_info << (QString::number(ntohs(tcp_h->windows_size)));
				data_info << (QString::number(ntohs(tcp_h->check_sum)));
				data_info << (QString::number(ntohs(tcp_h->urg_pointer)));
				data_info << (QString::number(tcp_h->ops));
				u_char* http_ana = (u_char*)(pkt_data  + ipv6_len + tcp_header_len);
				std::string temp_s = "";
				int count = 14 + ipv6_len + tcp_header_len;
				if (((strstr((char*)http_ana, "POST")) != NULL) || (strstr((char*)http_ana, "GET")) != NULL) {
					data[4] = "HTTP";
					pkt_count[HTTP]++;
					data_info << "HTTP";
					while (count < header->caplen) {
						temp_s.push_back(*http_ana);
						http_ana++;
						count++;
					}
					data_info << QString::fromStdString(temp_s);
				}
			}
			//UDP的情况
			else if (ipv6_h->nh == 17) {
				pkt_count[UDP]++;
				data_info << "UDP";
				data[4] = "UDP";
				data_info<<(QString::number(ipv6_h->hlim));
				data_info<<(data[2]);
				data_info<<(data[3]);
				src_port = ntohs(udp_h->src_port);
				dest_port = ntohs(udp_h->dest_port);
				//填充源端与目的端
				data[5] = QString::number(src_port);
				data[6] = QString::number(dest_port);
				data_info<<(data[5]);
				data_info<<(data[6]);
				data_info<<(QString::number(udp_h->udp_len));
				data_info<<(QString::number(tcp_h->check_sum));
				data_info<<(QString::number(udp_h->data));
			}
			//ICMP协议的情况
			else if (ipv6_h->nh == 1) {
				pkt_count[ICMP]++;
				data[4] = "ICMP";
				data_info << "ICMP";
				data_info<<(data[2]);
				data_info<<(data[3]);
				data_info<<(QString::number(ip_h->op_pad));
				data[5] = data[6] = "---";
				data_info<<(QString::number(icmp_h->type));
				data_info<<(QString::number(icmp_h->code));
				data_info<<(QString::number(icmp_h->check_sum));
				data_info<<(QString::number(icmp_h->id));
				data_info<<(QString::number(icmp_h->seq));
			}
			else {
				pkt_count[OTHER]++;
				data_info << "OTHER";
				data_info << (QString::number(ipv6_h->hlim));
				data_info << (data[2]);
				data_info << (data[3]);
				data[4] = data[5] = data[6] = "OTHER";
			}
		}
		//ARP的情况
		else if (n_type == 2054) {
			pkt_count[ARP]++;
			data_info << "ARP";
			data[4] = "ARP";
			data_info<<(QString::number(arp_h->ar_hw));
			for (int i = 0; i < 4; ++i) {
				tmp += QString::number(arp_h->ar_srcip[i]);
				if (i != 3) {
					tmp += ".";
				}
			}
			data[2] = tmp;
			tmp.clear();
			for (int i = 0; i < 4; ++i) {
				tmp += QString::number(arp_h->ar_destip[i]);
				if (i != 3) {
					tmp += ".";
				}
			}
			data[3] = tmp;
			tmp.clear();
			u_int arp_len = 7 * 4;
			udp_h = (UdpHeader*)(arp_h+arp_len);
			tcp_h = (TcpHeader*)(arp_h + arp_len);
			icmp_h = (IcmpHeader*)(arp_h + arp_len);
			//TCP报文的情况
			if (arp_h->ar_port == 6) {
				pkt_count[TCP]++;
				data_info << "TCP";
				data[4] = "TCP";
				data_info<<(QString::number(arp_h->ar_hln));
				data_info<<(QString::number(arp_h->ar_pln));
				data_info<<(QString::number(arp_h->ar_op));
				data_info<<(src_mac);
				data_info<<(data[2]);
				data_info<<(dest_mac);
				data_info<<(data[3]);
				src_port = ntohs(tcp_h->src_port);
				dest_port = ntohs(tcp_h->dest_port);
				//填充源端与目的端
				data[5] = QString::number(src_port);
				data[6] = QString::number(dest_port);
				data_info<<(data[5]);
				data_info<<(data[6]);
				data_info<<(QString::number(tcp_h->seq));
				data_info<<(QString::number(tcp_h->ack));
				data_info<<(QString::number(tcp_h->hl_flag & 0xf000));
				data_info << (QString::number(ntohs(tcp_h->seq)));
				data_info << (QString::number(ntohs(tcp_h->ack)));
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0xf000 >> 10));//tcp首部长度
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0020 >> 5));
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0010 >> 4));
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0008 >> 3));
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0004 >> 2));
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0002 >> 1));
				data_info << (QString::number(ntohs(tcp_h->hl_flag) & 0x0001));
				data_info << (QString::number(ntohs(tcp_h->windows_size)));
				data_info << (QString::number(ntohs(tcp_h->check_sum)));
				data_info << (QString::number(ntohs(tcp_h->urg_pointer)));
				data_info << (QString::number(tcp_h->ops));
			}
			//UDP的情况
			else if (arp_h->ar_port == 17) {
				pkt_count[UDP]++;
				data_info << "UDP";
				data[4] = "UDP";
				data_info<<(QString::number(arp_h->ar_hln));
				data_info<<(QString::number(arp_h->ar_pln));
				data_info<<(QString::number(arp_h->ar_op));
				data_info<<(src_mac);
				data_info<<(data[2]);
				data_info<<(dest_mac);
				data_info<<(data[3]);
				src_port = ntohs(udp_h->src_port);
				dest_port = ntohs(udp_h->dest_port);
				//填充源端与目的端
				data[5] = QString::number(src_port);
				data[6] = QString::number(dest_port);
				data_info<<(data[5]);
				data_info<<(data[6]);
				data_info<<(QString::number(udp_h->udp_len));
				data_info<<(QString::number(tcp_h->check_sum));
				data_info<<(QString::number(udp_h->data));
			}
			//ICMP协议的情况
			else if (arp_h->ar_port == 1) {
				pkt_count[ICMP]++;
				data[4] = "ICMP";
				data_info << "ICMP";
				data_info<<(QString::number(arp_h->ar_hln));
				data_info<<(QString::number(arp_h->ar_pln));
				data_info<<(QString::number(arp_h->ar_op));
				data_info<<(src_mac);
				data_info<<(data[2]);
				data_info<<(dest_mac);
				data_info<<(data[3]);
				data[5] = data[6] = "---";
				data_info<<(QString::number(icmp_h->type));
				data_info<<(QString::number(icmp_h->code));
				data_info<<(QString::number(icmp_h->check_sum));
				data_info<<(QString::number(icmp_h->id));
				data_info<<(QString::number(icmp_h->seq));
			}
			else {
				pkt_count[OTHER]++;
				data_info << "OTHER";
				data_info << "OTHER";
				data_info<<(QString::number(arp_h->ar_hln));
				data_info<<(QString::number(arp_h->ar_pln));
				data_info<<(QString::number(arp_h->ar_op));
				data_info<<(src_mac);
				data_info<<(data[2]);
				data_info<<(dest_mac);
				data_info<<(data[3]);
				data[5] = data[6] = "OTHER";
			}
		}
		else 
		{
			pkt_count[OTHER]++;
			data_info << "OTHER";
			for (int i = 2; i < 7; ++i) {
				data[i] = "OTHER";
			}
		}
		QStringList data_tmp;
		QString temp_s = "";
		for (int i = 0; i < 7; ++i) {
			data_tmp << data[i];
		}
		for (u_int i = 0; i < header->caplen; ++i) {
			temp_s += QString("%1").arg((*pkt_data), 2, 16, QLatin1Char('0'));
			pkt_data++;
		}
		if (!filter_http) {
			(*pkt_vector).push_back(data_info);
			(*raw_pkt_data).push_back(temp_s);
			temp_s.clear();
			emit send_to_main(data_tmp, row_index);
			row_index++;
		}
		else {
			if (data[4] == "HTTP") {
				(*pkt_vector).push_back(data_info);
				(*raw_pkt_data).push_back(temp_s);
				temp_s.clear();
				emit send_to_main(data_tmp, row_index);
				row_index++;
			}
		}
	}
}
bool WorkThread::set_filter(QString rule)
{	
	if (rule == "ALL") {
		return true;
	}
	char* rule_;
	//将获取到的字符串转换成pcap_compile可以接受的设置类型
	QByteArray ba = rule.toLatin1();
	rule_ = ba.data();
	//将规则与掩码设置到bfg
	//TODO::将错误信息以信号形式传输到主线程
	if (pcap_compile(adhandle,&hcode,rule_,1,netmask) <0) {
		return false;
	}
	//TODO::将错误信息以信号形式传输到主线程
	//设置捕获规则
	if (pcap_setfilter(adhandle, &hcode) < 0) {
		return false;
	}
	return true;
}


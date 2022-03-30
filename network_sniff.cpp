#include "network_sniff.h"
#include "http_shower.h"
#include<iostream>
network_sniff::network_sniff(QWidget *parent)
    : QMainWindow(parent)
{   
    QString filter_rule[] = { "ALL", "ip", "ip6", "icmp", "arp", "tcp", "udp","ALL"};
    ui.setupUi(this);
    is_stop = false; 
    //添加信号与槽的链接
    //网卡选择器
    connect(ui.cb_netc, QOverload<int>::of(&QComboBox::activated), [=](int index) {
        this->select_index = index;
     });
    ////过滤规则绑定
    connect(ui.cb_grahc, QOverload<int>::of(&QComboBox::activated), [=](int index) {
        if (index == 8) {
            filter_http = false;
            Dialog* dia = new Dialog(this);
            dia->show();
            connect(dia, &Dialog::send_rule, [=](QString rule) {
                this->selected_filter = rule;
                });
        }
        else if (index == 7) {
            this->selected_filter = filter_rule[index];
            filter_http = true;
        }
        else {
            filter_http = false;
            this->selected_filter = filter_rule[index];
        }
     });
    //右键实现流的追踪功能
    connect(ui.tw_allpkt, &QTableWidget::customContextMenuRequested, [=](const QPoint& pos) {
        add_menu(pos);
        });
    connect(ui.psb_start, &QPushButton::clicked, [=]() {
        Start();
        work_thread = new WorkThread(this, all_device, select_index, selected_filter, &pkt_vector,&raw_pkt_data,pkt_count,filter_http);
        //设置queueedconnection 提升主从线程的用户体验
        work_thread->start();
        connect(work_thread,&WorkThread::send_to_main,this,&network_sniff::add_to_view,Qt::QueuedConnection);
        });
    connect(ui.psb_stop, &QPushButton::clicked, [=]() {

        if (work_thread&&work_thread->isRunning()) {
            work_thread->exit(0);
            delete work_thread;
            work_thread = nullptr;
        }
        Stop();
        if(work_thread)
        disconnect(work_thread);
        });
    connect(ui.tw_allpkt, &QTableWidget::clicked, [=] {
        show_pkt_detail();
        show_pkt_bin();
        });

    connect(ui.psb_total, &QPushButton::clicked, [=] {
        count_dialog* temp_dialog = new count_dialog(this);
        temp_dialog->show_the_count(this->pkt_count);
        temp_dialog->show();
    });
}

void network_sniff::get_dev_list(QVector<DevInfo> &dev_list)
{   
    if (pcap_findalldevs(&all_device, err_buf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs:%s\n", err_buf);
        return;
    }
    DevInfo dev_info;
    for (now_device = all_device; now_device; now_device = now_device->next) {
        dev_info.name = now_device->name;
        dev_info.description = "no description!\n";
        if (now_device->description) {
            dev_info.description = now_device->description;
        }
        dev_list.push_back(dev_info);
    }
    return;
}

void network_sniff::ini()
{
    //初始化按钮状态
    ui.psb_start->setEnabled(true);
    ui.psb_stop->setEnabled(false);
    ui.cb_netc->setEditable(false);
    //获取设备信息
    QVector<DevInfo> devlist;
    get_dev_list(devlist);
    //允许获取右键来追踪TCP流
    ui.tw_allpkt->setContextMenuPolicy(Qt::CustomContextMenu);
    if (devlist.size() <= 0) {
        ui.cb_netc->addItem("please check your permison ,use admin\n");
        ui.cb_netc->setCurrentIndex(0);
    }
    ui.cb_netc->setView(new QListView);
    for (auto dev_info : devlist) {
        ui.cb_netc->addItem(dev_info.description);
    }
    ui.cb_netc->setCurrentIndex(0);
    select_index = 0;
    QString filter_rule[] = { "ALL", "IPV4", "IPV6", "ICMP", "ARP", "TCP", "UDP" ,"HTTP","USER_INPUT"};
    for (auto filter_r : filter_rule) {
        ui.cb_grahc->addItem(filter_r);
    }
    ui.cb_grahc->setCurrentIndex(0);
    select_f_index = 0;
    ui.tw_allpkt->clear();
    ui.te_pktd->clear();
    ui.qtw_pktd->clear();
    QStringList col_name;
    col_name <<QString::fromLocal8Bit("时间") << QString::fromLocal8Bit("包长") << QString::fromLocal8Bit("源地址") << QString::fromLocal8Bit("目的地址") << 
        QString::fromLocal8Bit("协议") << QString::fromLocal8Bit("源端口") << QString::fromLocal8Bit("目的端口");
    ui.tw_allpkt->horizontalHeader()->setVisible(true);
    ui.tw_allpkt->setColumnCount(7);
    ui.tw_allpkt->setHorizontalHeaderLabels(col_name);
    QFont header_font;
    //字体加粗设置斜体
    header_font.setBold(true);
    header_font.setItalic(true);
    ui.tw_allpkt->horizontalHeader()->setFont(header_font);
    ui.tw_allpkt->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui.tw_allpkt->setSelectionMode(QAbstractItemView::SingleSelection);
    ui.tw_allpkt->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui.tw_allpkt->horizontalHeader()->setStretchLastSection(true);
    //自动调整大小
    for (int i = 0; i <= 6; ++i) {
        ui.tw_allpkt->horizontalHeader()->setSectionResizeMode(i,QHeaderView::ResizeToContents);
    }

}

void network_sniff::ui_after_start()
{
    //按钮状态
    ui.psb_start->setEnabled(false);
    ui.psb_stop->setEnabled(true);
    ui.cb_grahc->setEnabled(false);
    ui.cb_netc->setEnabled(false);
    ui.tw_allpkt->setRowCount(0);
    ui.te_pktd->clear();
    ui.qtw_pktd->clear();
    pkt_vector.clear();
    raw_pkt_data.clear();
}

void network_sniff::ui_after_stop()
{
    ui.psb_start->setEnabled(true);
    ui.psb_stop->setEnabled(false);
    ui.cb_grahc->setEnabled(true);
    ui.cb_netc->setEnabled(true);
}
//包分析器 
void network_sniff::show_pkt_detail()
{
    auto index = ui.tw_allpkt->currentRow();
    if (index >= pkt_vector.size()) {
        QTreeWidgetItem* other = new QTreeWidgetItem(ui.qtw_pktd, QStringList("Others"));
        other->setExpanded(true);
        return;
    }
    QStringList data_info = pkt_vector[index];
    int datalen = data_info.size();
    ui.qtw_pktd->clear();
    //添加并且展示以太网信息
    QTreeWidgetItem* ethernet = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("物理地址")));
    ethernet->setExpanded(true);
    QString temp = "";
    if (datalen >= 3) {
        temp = QString::fromLocal8Bit("源MAC:") + data_info.at(0);
        ethernet->addChild(new QTreeWidgetItem(ethernet, QStringList(temp)));
        temp.clear();
        temp = QString::fromLocal8Bit("目地MAC:") + data_info[1];
        ethernet->addChild(new QTreeWidgetItem(ethernet, QStringList(temp)));
        temp.clear();
        temp = QString::fromLocal8Bit("协议:") + data_info[2];
        ethernet->addChild(new QTreeWidgetItem(ethernet, QStringList(temp)));
    }
    temp.clear();
    //为IPV4的情况
    if (datalen > 2 && data_info[2] == "IPV4") {
        QTreeWidgetItem* ipv4 = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("IPV4包")));
        ipv4->setExpanded(true);
        //与捕获的过程正好相反
        int cur_index = 3;
        if (datalen >= 9) {
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("首部长度:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("区分服务:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("总长度:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("标识:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("标志:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("片偏移:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("TTL:") + data_info[cur_index++])));
            //cur_index = 10
            if (datalen >= 30 && data_info[cur_index] == "TCP") {
                QTreeWidgetItem* tcp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("TCP包")));
                tcp->setExpanded(true);
                cur_index++;
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("CRC校验和:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("源地址:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("目的地址:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("选项字段:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("源端口(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("目的端口(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SEQ序号:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACK序号:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("头部长度:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("URG:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACK位:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("PSH:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("RST:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SYN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("FIN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("窗口大小:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("校验和:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("紧急指针:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("选项:") + data_info[cur_index++])));
                if (cur_index < datalen&&data_info[cur_index] == "HTTP") {
                    cur_index++;
                    http_shower_dialog* new_d = new http_shower_dialog(data_info[cur_index],this);
                    new_d->show();
                }
            }
            else if (datalen >= 20 && data_info[cur_index] == "UDP") {
                QTreeWidgetItem* udp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("UDP包")));
                udp->setExpanded(true);
                cur_index++;
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("CRC校验和:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("源地址:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("目的地址:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("选项字段:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("源端口(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("目的端口(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("长度:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("校验和:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("数据:") + data_info[cur_index++])));
            }
            else if (datalen >= 20 && data_info[cur_index] == "ICMP") {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("ICMP包")));
                icmp->setExpanded(true);
                cur_index++;
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("CRC校验和:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("源地址:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("目的地址:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("选项字段:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("类型:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("代码:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("校验和:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("ID:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("SEQ:") + data_info[cur_index++])));
            }
            else {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("其他类型包")));
            }
        }
    }
    //IPV6的情况
    else if (data_info[2] == "IPV6") {
        QTreeWidgetItem* ipv6 = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("ipv6包")));
        ipv6->setExpanded(true);
        //与捕获的过程正好相反
        int cur_index = 3;
        if (datalen >= 5) {
            ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("通信类:") + data_info[cur_index++])));
            ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("流标签:") + data_info[cur_index++])));
            ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("有效负荷长度:") + data_info[cur_index++])));

            if (datalen >= 24 && data_info[cur_index] == "TCP") {
                QTreeWidgetItem* tcp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("TCP包")));
                tcp->setExpanded(true);
                cur_index++;//6
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("下一个头:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("源地址:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("目的地址:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("源端口(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("目的端口(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SEQ序号:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACK序号:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("头部长度:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("URG:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACK位:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("PSH:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("RST:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SYN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("FIN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("窗口大小:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("校验和:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("紧急指针:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("选项:") + data_info[cur_index++])));
                if (cur_index < datalen && data_info[cur_index] == "HTTP") {
                    QTreeWidgetItem* http = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("HTTP请求")));
                    cur_index++;
                    http->addChild(new QTreeWidgetItem(http, QStringList(QString::fromLocal8Bit("报文:") + data_info[cur_index++])));
                }
            }
            else if (datalen >= 14 && data_info[cur_index] == "UDP") {
                QTreeWidgetItem* udp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("UDP包")));
                udp->setExpanded(true);
                cur_index++;
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("下一个头:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("源地址:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("目的地址:") + data_info[cur_index++])));;
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("源端口(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("目的端口(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("长度:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("校验和:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("数据:") + data_info[cur_index++])));
            }
            else if (datalen >= 14 && data_info[cur_index] == "ICMP") {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("ICMP包")));
                icmp->setExpanded(true);
                cur_index++;
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("下一个头:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("源地址:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("目的地址:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("类型:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("代码:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("校验和:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("ID:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("SEQ:") + data_info[cur_index++])));
            }
            else {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("其他类型包")));
            }
        }
    }
    else if (data_info[2] == "ARP") {
        QTreeWidgetItem* arp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("ARP包")));
        arp->setExpanded(true);
        //与捕获的过程正好相反
        int cur_index = 3;
        if (datalen >= 4) {
            arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("硬件类型:") + data_info[cur_index++])));
            if (datalen >= 27 && data_info[cur_index] == "TCP") {
                QTreeWidgetItem* tcp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("TCP包")));
                tcp->setExpanded(true);
                cur_index++;//4
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("硬件地址长度:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("协议长度:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("操作类型:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("发送方MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("发送方IP:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("目的MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("目的IP:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("源端口(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("目的端口(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SEQ序号:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACK序号:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("头部长度:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("URG:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACK位:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("PSH:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("RST:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SYN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("FIN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("窗口大小:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("校验和:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("紧急指针:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("选项:") + data_info[cur_index++])));
                if (cur_index < datalen&& data_info[cur_index] == "HTTP") {
                    QTreeWidgetItem* ipv4 = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("HTTP")));
                }
            }
            else if (datalen >= 17 && data_info[cur_index] == "UDP") {
                QTreeWidgetItem* udp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("UDP包")));
                udp->setExpanded(true);
                cur_index++;
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("硬件地址长度:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("协议长度:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("操作类型:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("发送方MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("发送方IP:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("目的MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("目的IP:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("源端口(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("目的端口(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("长度:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("校验和:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("数据:") + data_info[cur_index++])));
            }
            else if (datalen >= 17 && data_info[cur_index] == "ICMP") {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("ICMP包")));
                icmp->setExpanded(true);
                cur_index++;
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("硬件地址长度:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("协议长度:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("操作类型:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("发送方MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("发送方IP:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("目的MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("目的IP:") + data_info[cur_index++])));;
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("类型:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("代码:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("校验和:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("ID:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("SEQ:") + data_info[cur_index++])));
            }
            else {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("其他类型包")));
            }
        }
        else {

        }
    }
}

void network_sniff::show_pkt_bin()
{
    auto index = ui.tw_allpkt->currentRow();
    ui.te_pktd->clear();
    ui.te_pktd->insertPlainText(QString::fromLocal8Bit("原始数据"));
    ui.te_pktd->insertPlainText("\n");
    ui.te_pktd->insertPlainText(raw_pkt_data[index]);   
}

void network_sniff::add_menu(const QPoint& pos)
{
    auto index = ui.tw_allpkt->currentRow();
    QMenu* new_menu = new QMenu(ui.tw_allpkt);
    QAction* new_action = new QAction();
    new_action->setText(QString::fromLocal8Bit("TCP流追踪"));

    
    connect(new_action, &QAction::triggered, [=]() {
        //新建一个工作线程进行流追踪

        if (pkt_vector[index][10] != "TCP") {
            http_shower_dialog* new_d = new http_shower_dialog(QString::fromLocal8Bit("请选择TCP流进行捕获"), this);
            new_d->show();
        }
        else{
            QString follow_rule = QString("((src net ");
            follow_rule += pkt_vector[index][13];
            follow_rule += QString(" and dst net ");
            follow_rule += pkt_vector[index][12];
            follow_rule += QString(" )");
            follow_rule += QString(" or (src net ");
            follow_rule += pkt_vector[index][12];
            follow_rule += QString(" and dst net ");
            follow_rule += pkt_vector[index][13];
            follow_rule += QString(" ))");
            follow_rule += QString("and ( port ");
            follow_rule += QString(pkt_vector[index][15]) + QString(" or port ") + QString(pkt_vector[index][16])
                + QString(")");
            selected_filter = follow_rule;
            if (work_thread && work_thread->isRunning()) {
                work_thread->exit(0);
                delete work_thread;
                work_thread = nullptr;
            }
            Stop();
            if (work_thread)
                disconnect(work_thread);
            Start();
            work_thread = new WorkThread(this, all_device, select_index, selected_filter, &pkt_vector, &raw_pkt_data, pkt_count, filter_http);
            //设置queueedconnection 提升主从线程的用户体验
            work_thread->start();
            connect(work_thread, &WorkThread::send_to_main, this, &network_sniff::add_to_view, Qt::QueuedConnection);
            http_shower_dialog* tcp_follower = new http_shower_dialog(QString(""), this);
        }
        }
    );
    new_menu->addAction(new_action);
    new_menu->exec(QCursor::pos());
}

void network_sniff::Stop()
{
    ui_after_stop();
}
void network_sniff::Start()
{
    ui_after_start();
}


void network_sniff::add_to_view(QStringList data, int row_index)
{
   ui.tw_allpkt->insertRow(row_index);
    //行格式:时间" << "包长" << "源地址" << "目的地址" << "协议" << "源端口" << "目的端口"
    for (int k = 0; k <= 6; ++k) {
        ui.tw_allpkt->setItem(row_index,k,new QTableWidgetItem(data[k]));
    }
    for (int i = 0; i <= 6; ++i) {
        ui.tw_allpkt->item(row_index,i)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
        ui.tw_allpkt->item(row_index,i)->setBackgroundColor(QColor(170,191,240));
    }
}
QString network_sniff::recv_filter_rule() {
    return selected_filter;
}

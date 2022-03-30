#include "network_sniff.h"
#include "http_shower.h"
#include<iostream>
network_sniff::network_sniff(QWidget *parent)
    : QMainWindow(parent)
{   
    QString filter_rule[] = { "ALL", "ip", "ip6", "icmp", "arp", "tcp", "udp","ALL"};
    ui.setupUi(this);
    is_stop = false; 
    //����ź���۵�����
    //����ѡ����
    connect(ui.cb_netc, QOverload<int>::of(&QComboBox::activated), [=](int index) {
        this->select_index = index;
     });
    ////���˹����
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
    //�Ҽ�ʵ������׷�ٹ���
    connect(ui.tw_allpkt, &QTableWidget::customContextMenuRequested, [=](const QPoint& pos) {
        add_menu(pos);
        });
    connect(ui.psb_start, &QPushButton::clicked, [=]() {
        Start();
        work_thread = new WorkThread(this, all_device, select_index, selected_filter, &pkt_vector,&raw_pkt_data,pkt_count,filter_http);
        //����queueedconnection ���������̵߳��û�����
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
    //��ʼ����ť״̬
    ui.psb_start->setEnabled(true);
    ui.psb_stop->setEnabled(false);
    ui.cb_netc->setEditable(false);
    //��ȡ�豸��Ϣ
    QVector<DevInfo> devlist;
    get_dev_list(devlist);
    //�����ȡ�Ҽ���׷��TCP��
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
    col_name <<QString::fromLocal8Bit("ʱ��") << QString::fromLocal8Bit("����") << QString::fromLocal8Bit("Դ��ַ") << QString::fromLocal8Bit("Ŀ�ĵ�ַ") << 
        QString::fromLocal8Bit("Э��") << QString::fromLocal8Bit("Դ�˿�") << QString::fromLocal8Bit("Ŀ�Ķ˿�");
    ui.tw_allpkt->horizontalHeader()->setVisible(true);
    ui.tw_allpkt->setColumnCount(7);
    ui.tw_allpkt->setHorizontalHeaderLabels(col_name);
    QFont header_font;
    //����Ӵ�����б��
    header_font.setBold(true);
    header_font.setItalic(true);
    ui.tw_allpkt->horizontalHeader()->setFont(header_font);
    ui.tw_allpkt->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui.tw_allpkt->setSelectionMode(QAbstractItemView::SingleSelection);
    ui.tw_allpkt->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui.tw_allpkt->horizontalHeader()->setStretchLastSection(true);
    //�Զ�������С
    for (int i = 0; i <= 6; ++i) {
        ui.tw_allpkt->horizontalHeader()->setSectionResizeMode(i,QHeaderView::ResizeToContents);
    }

}

void network_sniff::ui_after_start()
{
    //��ť״̬
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
//�������� 
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
    //��Ӳ���չʾ��̫����Ϣ
    QTreeWidgetItem* ethernet = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("�����ַ")));
    ethernet->setExpanded(true);
    QString temp = "";
    if (datalen >= 3) {
        temp = QString::fromLocal8Bit("ԴMAC:") + data_info.at(0);
        ethernet->addChild(new QTreeWidgetItem(ethernet, QStringList(temp)));
        temp.clear();
        temp = QString::fromLocal8Bit("Ŀ��MAC:") + data_info[1];
        ethernet->addChild(new QTreeWidgetItem(ethernet, QStringList(temp)));
        temp.clear();
        temp = QString::fromLocal8Bit("Э��:") + data_info[2];
        ethernet->addChild(new QTreeWidgetItem(ethernet, QStringList(temp)));
    }
    temp.clear();
    //ΪIPV4�����
    if (datalen > 2 && data_info[2] == "IPV4") {
        QTreeWidgetItem* ipv4 = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("IPV4��")));
        ipv4->setExpanded(true);
        //�벶��Ĺ��������෴
        int cur_index = 3;
        if (datalen >= 9) {
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("�ײ�����:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("���ַ���:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("�ܳ���:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("��ʶ:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("��־:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("Ƭƫ��:") + data_info[cur_index++])));
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("TTL:") + data_info[cur_index++])));
            //cur_index = 10
            if (datalen >= 30 && data_info[cur_index] == "TCP") {
                QTreeWidgetItem* tcp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("TCP��")));
                tcp->setExpanded(true);
                cur_index++;
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("CRCУ���:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("Դ��ַ:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("Ŀ�ĵ�ַ:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("ѡ���ֶ�:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("Դ�˿�(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("Ŀ�Ķ˿�(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SEQ���:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACK���:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ͷ������:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("URG:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACKλ:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("PSH:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("RST:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SYN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("FIN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("���ڴ�С:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("У���:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("����ָ��:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ѡ��:") + data_info[cur_index++])));
                if (cur_index < datalen&&data_info[cur_index] == "HTTP") {
                    cur_index++;
                    http_shower_dialog* new_d = new http_shower_dialog(data_info[cur_index],this);
                    new_d->show();
                }
            }
            else if (datalen >= 20 && data_info[cur_index] == "UDP") {
                QTreeWidgetItem* udp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("UDP��")));
                udp->setExpanded(true);
                cur_index++;
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("CRCУ���:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("Դ��ַ:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("Ŀ�ĵ�ַ:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("ѡ���ֶ�:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("Դ�˿�(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("Ŀ�Ķ˿�(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("У���:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
            }
            else if (datalen >= 20 && data_info[cur_index] == "ICMP") {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("ICMP��")));
                icmp->setExpanded(true);
                cur_index++;
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("CRCУ���:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("Դ��ַ:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("Ŀ�ĵ�ַ:") + data_info[cur_index++])));
                ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(QString::fromLocal8Bit("ѡ���ֶ�:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("У���:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("ID:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("SEQ:") + data_info[cur_index++])));
            }
            else {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("�������Ͱ�")));
            }
        }
    }
    //IPV6�����
    else if (data_info[2] == "IPV6") {
        QTreeWidgetItem* ipv6 = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("ipv6��")));
        ipv6->setExpanded(true);
        //�벶��Ĺ��������෴
        int cur_index = 3;
        if (datalen >= 5) {
            ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("ͨ����:") + data_info[cur_index++])));
            ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("����ǩ:") + data_info[cur_index++])));
            ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("��Ч���ɳ���:") + data_info[cur_index++])));

            if (datalen >= 24 && data_info[cur_index] == "TCP") {
                QTreeWidgetItem* tcp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("TCP��")));
                tcp->setExpanded(true);
                cur_index++;//6
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("��һ��ͷ:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("Դ��ַ:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("Ŀ�ĵ�ַ:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("Դ�˿�(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("Ŀ�Ķ˿�(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SEQ���:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACK���:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ͷ������:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("URG:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACKλ:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("PSH:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("RST:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SYN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("FIN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("���ڴ�С:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("У���:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("����ָ��:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ѡ��:") + data_info[cur_index++])));
                if (cur_index < datalen && data_info[cur_index] == "HTTP") {
                    QTreeWidgetItem* http = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("HTTP����")));
                    cur_index++;
                    http->addChild(new QTreeWidgetItem(http, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
                }
            }
            else if (datalen >= 14 && data_info[cur_index] == "UDP") {
                QTreeWidgetItem* udp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("UDP��")));
                udp->setExpanded(true);
                cur_index++;
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("��һ��ͷ:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("Դ��ַ:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("Ŀ�ĵ�ַ:") + data_info[cur_index++])));;
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("Դ�˿�(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("Ŀ�Ķ˿�(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("У���:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
            }
            else if (datalen >= 14 && data_info[cur_index] == "ICMP") {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("ICMP��")));
                icmp->setExpanded(true);
                cur_index++;
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("��һ��ͷ:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("Դ��ַ:") + data_info[cur_index++])));
                ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(QString::fromLocal8Bit("Ŀ�ĵ�ַ:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("У���:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("ID:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("SEQ:") + data_info[cur_index++])));
            }
            else {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("�������Ͱ�")));
            }
        }
    }
    else if (data_info[2] == "ARP") {
        QTreeWidgetItem* arp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("ARP��")));
        arp->setExpanded(true);
        //�벶��Ĺ��������෴
        int cur_index = 3;
        if (datalen >= 4) {
            arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Ӳ������:") + data_info[cur_index++])));
            if (datalen >= 27 && data_info[cur_index] == "TCP") {
                QTreeWidgetItem* tcp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("TCP��")));
                tcp->setExpanded(true);
                cur_index++;//4
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Ӳ����ַ����:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Э�鳤��:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("��������:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("���ͷ�MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("���ͷ�IP:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Ŀ��MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Ŀ��IP:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("Դ�˿�(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("Ŀ�Ķ˿�(port):") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SEQ���:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACK���:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ͷ������:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("URG:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ACKλ:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("PSH:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("RST:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("SYN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("FIN:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("���ڴ�С:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("У���:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("����ָ��:") + data_info[cur_index++])));
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(QString::fromLocal8Bit("ѡ��:") + data_info[cur_index++])));
                if (cur_index < datalen&& data_info[cur_index] == "HTTP") {
                    QTreeWidgetItem* ipv4 = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("HTTP")));
                }
            }
            else if (datalen >= 17 && data_info[cur_index] == "UDP") {
                QTreeWidgetItem* udp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("UDP��")));
                udp->setExpanded(true);
                cur_index++;
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Ӳ����ַ����:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Э�鳤��:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("��������:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("���ͷ�MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("���ͷ�IP:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Ŀ��MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Ŀ��IP:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("Դ�˿�(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("Ŀ�Ķ˿�(port):") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("У���:") + data_info[cur_index++])));
                udp->addChild(new QTreeWidgetItem(udp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
            }
            else if (datalen >= 17 && data_info[cur_index] == "ICMP") {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("ICMP��")));
                icmp->setExpanded(true);
                cur_index++;
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Ӳ����ַ����:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Э�鳤��:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("��������:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("���ͷ�MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("���ͷ�IP:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Ŀ��MAC:") + data_info[cur_index++])));
                arp->addChild(new QTreeWidgetItem(arp, QStringList(QString::fromLocal8Bit("Ŀ��IP:") + data_info[cur_index++])));;
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("����:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("У���:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("ID:") + data_info[cur_index++])));
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(QString::fromLocal8Bit("SEQ:") + data_info[cur_index++])));
            }
            else {
                QTreeWidgetItem* icmp = new QTreeWidgetItem(ui.qtw_pktd, QStringList(QString::fromLocal8Bit("�������Ͱ�")));
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
    ui.te_pktd->insertPlainText(QString::fromLocal8Bit("ԭʼ����"));
    ui.te_pktd->insertPlainText("\n");
    ui.te_pktd->insertPlainText(raw_pkt_data[index]);   
}

void network_sniff::add_menu(const QPoint& pos)
{
    auto index = ui.tw_allpkt->currentRow();
    QMenu* new_menu = new QMenu(ui.tw_allpkt);
    QAction* new_action = new QAction();
    new_action->setText(QString::fromLocal8Bit("TCP��׷��"));

    
    connect(new_action, &QAction::triggered, [=]() {
        //�½�һ�������߳̽�����׷��

        if (pkt_vector[index][10] != "TCP") {
            http_shower_dialog* new_d = new http_shower_dialog(QString::fromLocal8Bit("��ѡ��TCP�����в���"), this);
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
            //����queueedconnection ���������̵߳��û�����
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
    //�и�ʽ:ʱ��" << "����" << "Դ��ַ" << "Ŀ�ĵ�ַ" << "Э��" << "Դ�˿�" << "Ŀ�Ķ˿�"
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

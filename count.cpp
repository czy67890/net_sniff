#include"count.h"
void count_dialog::show_the_count(int count[8]) {
	ui->le_arp->setText(QString::number(count[ARP]));
	ui->le_icmp->setText(QString::number(count[ICMP]));
	ui->le_v4->setText(QString::number(count[IPV4]));
	ui->le_v6->setText(QString::number(count[IPV6]));
	ui->le_tcp->setText(QString::number(count[TCP]));
	ui->le_udp->setText(QString::number(count[UDP]));
	ui->le_http->setText(QString::number(count[HTTP]));
}
count_dialog::count_dialog(QWidget *parent) :QDialog(parent),ui(new Ui::count_dialog){
	ui->setupUi(this);
}
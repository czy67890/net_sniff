#pragma once
#include"ui_count.h"
#include"data_struct.h"
//const static int IPV4 = 0;
//const static int IPV6 = 1;
//const static int ARP = 2;
//const static int TCP = 3;
//const static int UDP = 4;
//const static int ICMP = 5;
//const static int HTTP = 6;
//const static int OTHER = 7;
class count_dialog :public QDialog{
	Q_OBJECT
public:

	explicit count_dialog(QWidget* parent = nullptr);
	void show_the_count(int count[8]);
private:
	Ui::count_dialog* ui;
};
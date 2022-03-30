#pragma once
#include<QDialog>
#include"ui_filter_dialog.h"
class Dialog :public QDialog{
	Q_OBJECT
public:
	explicit Dialog(QWidget* parent = nullptr);
private:
	Ui::Dialog* ui;
signals:
	void send_rule(QString rule);
};
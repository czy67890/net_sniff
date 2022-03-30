#pragma once
#include"ui_show_http.h"
class  http_shower_dialog :public QDialog{
	Q_OBJECT
public:
	explicit http_shower_dialog(QString rule,QWidget* parent = nullptr);
private:
	Ui::http_shower_dialog* ui;
};
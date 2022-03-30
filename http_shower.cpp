#include "http_shower.h"
http_shower_dialog::http_shower_dialog(QString rule,QWidget* parent) :QDialog(parent), ui(new Ui::http_shower_dialog) {
	ui->setupUi(this);
	ui->http_shower->setText(rule);
}
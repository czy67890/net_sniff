#include"filter_dialog.h"
Dialog::Dialog(QWidget* parent):QDialog(parent),ui(new Ui::Dialog) {
	ui->setupUi(this);
	connect((ui->psb_input), &QPushButton::clicked, [=]() {
		emit send_rule(ui->le_input->text());
		this->close();
		});
	connect((ui->psb_cancel),&QPushButton::clicked, [=]() {
		emit send_rule("");
	});
}
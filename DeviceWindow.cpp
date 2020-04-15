//
// Created by 76971 on 2020/3/26.
//

#include "DeviceWindow.h"

DeviceWindow::DeviceWindow(controller *c, QWidget *parent)
        : QDialog(parent), ui(new Ui::DeviceWindow), _controller(c) {

    ui->setupUi(this);
    for (pcap_if_t *d = c->getDevices(); d != nullptr; d = d->next) {
        ui->device_choose->addItem(QString(d->name));
    }
    connect(ui->device_choose, SIGNAL(itemSelectionChanged()), this, SLOT(onChangeDeviceInfo()));
    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(onSelectDeviceOn()));
}

DeviceWindow::~DeviceWindow() {
    delete ui;
}

void DeviceWindow::onChangeDeviceInfo() {
    auto current = ui->device_choose->currentItem()->text();
    pcap_if_t *_on = _controller->getDevices();
    for (; _on != nullptr && current != QString(_on->name); _on = _on->next);
    _controller->setDevicesOn(_on);
    ui->device_info->setPlainText(_controller->getDeviceInfo());
}

void DeviceWindow::onSelectDeviceOn() {
    _controller->openDeviceLive();
    emit showStartButton();
    this->hide();
}

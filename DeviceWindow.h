//
// Created by 76971 on 2020/3/26.
//

#ifndef USNIFFER_DEVICEWINDOW_H
#define USNIFFER_DEVICEWINDOW_H

#include <QDialog>
#include "pcap.h"
#include "./ui_device.h"
#include "controller.h"

QT_BEGIN_NAMESPACE
namespace Ui {
    class DeviceWindow;
}
QT_END_NAMESPACE

class DeviceWindow : public QDialog {
Q_OBJECT
public:
    explicit DeviceWindow(controller *_controller, QWidget *parent = nullptr);

    ~DeviceWindow() override;

private:
    Ui::DeviceWindow *ui;
    controller *_controller;

private slots:

    void onChangeDeviceInfo();

    void onSelectDeviceOn();

signals:
    void showStartButton();
};


#endif //USNIFFER_DEVICEWINDOW_H

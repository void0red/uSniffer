//
// Created by 76971 on 2020/3/22.
//

#ifndef USNIFFER_VIEW_H
#define USNIFFER_VIEW_H

#include <QMainWindow>
#include "controller.h"
#include "DeviceWindow.h"
#include "./ui_view.h"
#include <QStandardItemModel>

QT_BEGIN_NAMESPACE
namespace Ui {
    class view;
}
QT_END_NAMESPACE

class view : public QMainWindow {
Q_OBJECT
public:
    explicit view(QWidget *parent = nullptr);

    ~view() override;

private:
    Ui::view *ui;
    controller *_controller;
    DeviceWindow *deviceWindow{};
    QStandardItemModel *model{};

    inline void initModel();

    inline void initPacketsTableView();

    inline void printPacketsTableView();

public slots:

    void openDeviceWindow();

    void startCapture();

    void stopCapture();

    void showInfo(const QModelIndex &current, const QModelIndex &previous);

    void filtering();
};

#endif //USNIFFER_VIEW_H

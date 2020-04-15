//
// Created by 76971 on 2020/3/22.
//

#include "view.h"


view::view(QWidget *parent) :
        QMainWindow(parent), ui(new Ui::view), _controller(new controller),
        deviceWindow(new DeviceWindow(_controller)) {

    model = new QStandardItemModel(this);

    ui->setupUi(this);
    connect(ui->deviceButton, SIGNAL(clicked()), this, SLOT(openDeviceWindow()));
    connect(this->deviceWindow, &DeviceWindow::showStartButton, this, [=] {
        ui->startButton->setEnabled(true);
    });
    connect(ui->startButton, SIGNAL(clicked()), this, SLOT(startCapture()));
    connect(ui->stopButton, SIGNAL(clicked()), this, SLOT(stopCapture()));
    connect(ui->filterInput, SIGNAL(returnPressed()), this, SLOT(filtering()));

    initPacketsTableView();

    ui->statusbar->showMessage("Powered by void0red. 2020");
}

view::~view() {
    delete ui;
    delete deviceWindow;
    delete _controller;
    delete model;
}

void view::openDeviceWindow() {
    this->deviceWindow->show();
}

void view::startCapture() {
    this->model->clear();
    initModel();

    this->ui->packetsInfoView->clear();
    this->ui->packetsHexView->clear();

    this->ui->startButton->setDisabled(true);
    this->_controller->startCapture();
    this->ui->stopButton->setEnabled(true);

}

void view::stopCapture() {
    this->ui->stopButton->setDisabled(true);
    this->_controller->stopCapture();

    printPacketsTableView();
}

void view::initModel() {
    model->setColumnCount(6);
    model->setHeaderData(0, Qt::Horizontal, "ID");
    model->setHeaderData(1, Qt::Horizontal, "TIME");
    model->setHeaderData(2, Qt::Horizontal, "TYPE");
    model->setHeaderData(3, Qt::Horizontal, "SRC");
    model->setHeaderData(4, Qt::Horizontal, "DST");
    model->setHeaderData(5, Qt::Horizontal, "LEN");
}

void view::initPacketsTableView() {
    ui->packetsTableView->setModel(model);
    ui->packetsTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    connect(ui->packetsTableView->selectionModel(),
            SIGNAL(currentRowChanged(const QModelIndex &, const QModelIndex &)),
            this,
            SLOT(showInfo(const QModelIndex &, const QModelIndex &)));
}

void view::printPacketsTableView() {

    auto packets = _controller->getPacketsList();
    for (int i = 0; i < packets.size(); ++i) {
        model->setItem(i, 0, new QStandardItem(QString("%1").arg(packets[i]->getId())));
        model->setItem(i, 1, new QStandardItem(packets[i]->getTime()));
        model->setItem(i, 2, new QStandardItem(packets[i]->getType()));
        model->setItem(i, 3, new QStandardItem(packets[i]->getSrc()));
        model->setItem(i, 4, new QStandardItem(packets[i]->getDst()));
        model->setItem(i, 5, new QStandardItem(QString("%1").arg(packets[i]->getPacketLen())));
    }
}

void view::showInfo(const QModelIndex &current, const QModelIndex &previous) {
    ui->packetsInfoView->clear();
    ui->packetsHexView->clear();

    int row = current.row();

    auto packets = _controller->getPacketsList();
    if (row < packets.size()) {

        for (auto packet = packets[row]; packet != nullptr; packet = packet->getNext()) {
            ui->packetsInfoView->append(packet->getInfo());
        }
        ui->packetsInfoView->moveCursor(QTextCursor::Start);

        ui->packetsHexView->setText(packets[row]->getHex());
        ui->packetsHexView->moveCursor(QTextCursor::Start);
    }
}

void view::filtering() {
    auto input = ui->filterInput->text();
    if (input.isEmpty())
        return;

    this->model->clear();
    initModel();
    ui->packetsInfoView->clear();
    ui->packetsHexView->clear();

    ui->filterInput->setDisabled(true);

    auto data = input.toLocal8Bit().data();
    _controller->startFilter(data);

    this->printPacketsTableView();

    ui->filterInput->setEnabled(true);
}

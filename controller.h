//
// Created by 76971 on 2020/3/26.
//

#ifndef USNIFFER_CONTROLLER_H
#define USNIFFER_CONTROLLER_H

#include <vector>
#include <QString>
#include <QStringBuilder>
#include <future>
#include "pcap.h"
#include "packets.h"

class controller {
private:
    pcap_if_t *devices{};
    pcap_if_t *devices_on{};
    pcap_t *handle{};
    const char *saveFileName = ".tmp.data";
    pcap_dumper_t *saveFileHandle{};
    char errbuf[PCAP_ERRBUF_SIZE]{};
    std::vector<packets *> packets_list{};
    std::future<void> status{};
public:
    controller();

    virtual ~controller();

    QString getDeviceInfo();

    int openDeviceLive();

    pcap_if_t *getDevices() const;

    void setDevicesOn(pcap_if_t *devicesOn);

    void startCapture();

    void stopCapture();

    const std::vector<packets *> &getPacketsList() const;

    void startFilter(const char* filterStr);
};


#endif //USNIFFER_CONTROLLER_H

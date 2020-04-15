//
// Created by 76971 on 2020/3/26.
//

#include "controller.h"

controller::controller() {
    pcap_findalldevs(&(this->devices), this->errbuf);
}

controller::~controller() {
    if (this->devices) {
        pcap_freealldevs(this->devices);
        this->devices = nullptr;
    }
    if (this->handle) {
        pcap_close(this->handle);
        this->handle = nullptr;
    }
    pcap_dump_close(this->saveFileHandle);
    remove(this->saveFileName);
    for (auto i : this->packets_list)
        delete i;
    this->packets_list.clear();
}

#define IPTOSBUFFERS    12

static char *iptos(u_long in) {
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char *p;

    p = (u_char *) &in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

#define ADDR_EXIST_AND_APPEND(p, buf, str) \
    do{ \
        if (p) { \
            (buf).append(QString::asprintf((str), \
            iptos(((struct sockaddr_in *)(p))->sin_addr.s_addr)) \
            ); \
        } \
    }while(0)

QString controller::getDeviceInfo() {
    QString buf;
    pcap_if_t *device = this->devices_on;

    if (device == nullptr)
        return QString("");

    buf.append(QString::asprintf("Name: %s\n", device->name));
    if (device->description)
        buf.append(QString::asprintf("Description: %s\n", device->description));
    else
        buf.append("(no description available)\n");

    buf.append(QString::asprintf("Loopback: %s\n", (device->flags & PCAP_IF_LOOPBACK) ? "yes" : "no"));

    for (pcap_addr_t *a = device->addresses; a != nullptr; a = a->next) {
        buf.append(QString::asprintf("Address Family: #%d\n", a->addr->sa_family));

        ADDR_EXIST_AND_APPEND(a->addr, buf, "Address: %s\n");
        ADDR_EXIST_AND_APPEND(a->netmask, buf, "Netmask: %s\n");
        ADDR_EXIST_AND_APPEND(a->broadaddr, buf, "Broadcast Address: %s\n");
        ADDR_EXIST_AND_APPEND(a->dstaddr, buf, "Destination Address: %s\n");
    }
    return buf;
}

int controller::openDeviceLive() {
    if (this->handle != nullptr) {
        pcap_close(this->handle);
        for (auto i : this->packets_list)
            delete i;
        this->packets_list.clear();
    }
    this->handle = pcap_open_live(this->devices_on->name, 65535, 1, 1000, this->errbuf);
    if (this->handle == nullptr)
        return -1;
    this->saveFileHandle = pcap_dump_open(this->handle, this->saveFileName);
    return 0;
}

pcap_if_t *controller::getDevices() const {
    return devices;
}

void controller::setDevicesOn(pcap_if_t *devicesOn) {
    devices_on = devicesOn;
}

void controller::startCapture() {
    this->status = std::async(std::launch::async, [&]() {
        const u_char *ret = nullptr;
        pcap_pkthdr header{};
        for (auto i = 0;;) {
            ret = pcap_next(this->handle, &header);
            if (ret == nullptr) {
                break;
            }
            auto p = packets::MakePackets(i, ret, &header);
            pcap_dump((u_char *) (this->saveFileHandle), &header, ret);
            this->packets_list.emplace_back(p);
            i += 1;
        }
    });
}

void controller::stopCapture() {
    pcap_breakloop(handle);
    this->status.get();
    pcap_dump_flush(this->saveFileHandle);
    pcap_dump_close(this->saveFileHandle);
}

const std::vector<packets *> &controller::getPacketsList() const {
    return packets_list;
}

void controller::startFilter(const char *filterStr) {
    if (this->handle == nullptr)
        return;

    pcap_close(this->handle);
    for (auto i : this->packets_list)
        delete i;
    this->packets_list.clear();

    this->handle = pcap_open_offline(this->saveFileName, this->errbuf);
    struct bpf_program fcode{};
    pcap_compile(this->handle, &fcode, filterStr, 1, 0xffffff);
    pcap_setfilter(this->handle, &fcode);

    const u_char *ret = nullptr;
    pcap_pkthdr header{};
    for (auto i = 0;;) {
        ret = pcap_next(this->handle, &header);
        if (ret == nullptr) {
            break;
        }
        auto p = packets::MakePackets(i, ret, &header);
        this->packets_list.emplace_back(p);
        i += 1;
    }
}

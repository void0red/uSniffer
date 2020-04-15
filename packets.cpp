//
// Created by 76971 on 2020/3/22.
//

#include <inaddr.h>
#include "packets.h"

int packets::getId() const {
    return id;
}


packets::packets(const u_char *data, int id, packets::PacketType type, pcap_pkthdr *header, packets *next)
        : data(data), next(next), id(id), packetType(type), header(header) {
}

QString packets::getType() {
    return QString(PacketTypeString[packetType]);
}

packets *packets::getPackets() {
    return this;
}

packets *packets::MakePackets(int id, const u_char *data, const pcap_pkthdr *header) {
    auto _data = new u_char[header->len]{};
    auto _header = new pcap_pkthdr;
    memcpy(_data, data, header->len);
    memcpy(_header, header, sizeof(pcap_pkthdr));

    auto eth = new ImplPackets::eth(_data, id, _header);
    return eth->getPackets();
}

QString &packets::getTime() {
    if (!time.isEmpty())
        return time;
    time_t local_tv_sec = header->ts.tv_sec;
    struct tm ltime{};
    localtime_s(&ltime, &local_tv_sec);
    char _time[16];
    strftime(_time, sizeof(_time), "%H:%M:%S", &ltime);
    int _m = header->ts.tv_usec / 10;
    time += QString("%1:%2").arg(_time).arg(_m, 5, 10, QChar('0'));
    return time;
}

int packets::getPacketLen() {
    if (this->header != nullptr)
        return header->len;
    return 0;
}

QString packets::getSrc() {
    return QString();
}

QString packets::getDst() {
    return QString();
}

packets::~packets() {
    if (this->header != nullptr) {
        delete header;
        header = nullptr;
    }

    if (this->data != nullptr && this->packetType == ETH) {
        delete data;
        data = nullptr;
    }

    auto p = this->next;
    while (p != nullptr) {
        auto pp = p;
        delete p;
        p = pp->next;
    }
}

packets *packets::getNext() const {
    return next;
}

QString &packets::getInfo() {
    return empty;
}

QString &packets::getHex() {
    if (!hex.isEmpty())
        return hex;

    auto p = this;
    while (p->next != nullptr) {
        p = p->next;
    }

    QByteArray array((const char *) (p->data), header->len);
    auto hexInfo = array.toHex();

    for (int i = 0; i < header->len; ++i) {
        hex.append(hexInfo.at(2 * i));
        hex.append(hexInfo.at(2 * i + 1));
        hex.append(' ');
        if ((i + 1) % 8 == 0) {
            hex.append(' ');
        }
        if ((i + 1) % 16 == 0) {
            hex.append('\n');
        }
    }

    return hex;
}

pcap_pkthdr *packets::getHeader() const {
    return header;
}

ImplPackets::eth::eth(const u_char *data, int id, pcap_pkthdr *header, packets *next)
        : packets(data, id, packets::ETH, header, next) {
    this->raw = (format *) data;

    ethType = packets::PacketType(ntohs(raw->type));
}

const u_char *ImplPackets::eth::getEthData() const {
    return (u_char *) raw + sizeof(format);
}

packets *ImplPackets::eth::getPackets() {
    if (ethType == packets::ETH_IP) {
        auto ip = new ImplPackets::ip(this->getEthData(), this->getId(), this->getHeader(), this);
        return ip->getPackets();
    } else if (ethType == packets::ETH_ARP) {
        auto arp = new ImplPackets::arp(this->getEthData(), this->getId(), this->getHeader(), this);
        return arp->getPackets();
    }
    return this;
}

QString &ImplPackets::eth::getInfo() {
    if (!info.isEmpty())
        return info;

    QByteArray destinationHost((const char *) (raw->destinationHost), 6);
    auto dst = destinationHost.toHex(':');
    QByteArray sourceHost((const char *) (raw->sourceHost), 6);
    auto src = sourceHost.toHex(':');

    info += QString("==============Ethernet Protocol=================\n"
                    "Destination Mac Address: %1\n"
                    "Source Mac Address: %2\n"
                    "Ethernet type: %3 (%4)").
            arg(QString(dst)).
            arg(QString(src)).
            arg(PacketTypeString[ethType]).
            arg(int(ethType), 4, 16, QChar('0'));

    return info;
}


QString ImplPackets::eth::getSrc() {
    return QString();
}

QString ImplPackets::eth::getDst() {
    return QString();
}

ImplPackets::ip::ip(const u_char *data, int id, pcap_pkthdr *header, packets *next)
        : packets(data, id, packets::ETH_IP, header, next) {
    this->raw = (format *) data;

    ipType = packets::PacketType(raw->protocol);

    struct sockaddr_in addr{};
    addr.sin_addr.S_un.S_addr = raw->sourceAddr;
    sourceIP = QString(inet_ntoa(addr.sin_addr));

    addr.sin_addr.S_un.S_addr = raw->destinationAddr;
    destinationIP = QString(inet_ntoa(addr.sin_addr));
}


const u_char *ImplPackets::ip::getIpData() const {
    return (u_char *) raw + sizeof(format);
}

packets *ImplPackets::ip::getPackets() {

    if (ipType == packets::IP_TCP) {
        auto tcp = new ImplPackets::tcp(this->getIpData(), this->getId(), this->getHeader(), this);
        return tcp->getPackets();
    } else if (ipType == packets::IP_UDP) {
        auto udp = new ImplPackets::udp(this->getIpData(), this->getId(), this->getHeader(), this);
        return udp->getPackets();
    } else if (ipType == packets::IP_ICMP) {
        auto icmp = new ImplPackets::icmp(this->getIpData(), this->getId(), this->getHeader(), this);
        return icmp->getPackets();
    }
    return this;
}

QString &ImplPackets::ip::getInfo() {
    if (!info.isEmpty())
        return info;

    info += QString("===================IP Protocol==================\n"
                    "Version: %1\n"
                    "Header Length: %2 bytes\n"
                    "Tos: %3\n"
                    "Total Length: %4\n"
                    "Identification: %5 (%6)\n"
                    "Flags: %7\n"
                    "Fragment offset: %8\n").
            arg(raw->version_headerLen >> 4u).
            arg((raw->version_headerLen & 0x0fu) * 4).
            arg(raw->tos).
            arg(ntohs(raw->len)).
            arg(ntohs(raw->identification), 4, 16, QChar('0')).
            arg(ntohs(raw->identification)).
            arg(ntohs(raw->flags_offset) >> 13u).
            arg(ntohs(raw->flags_offset) & 0x1fffu);

    info += QString("---Reserved bit: %1\n"
                    "---Don't fragment: %2\n"
                    "---More fragment: %3\n"
                    "Time to live: %4\n"
                    "Protocol Type: %5 (%6)\n"
                    "Header checksum: %7\n"
                    "Source: %8\n"
                    "Destination: %9\n").
            arg((ntohs(raw->flags_offset) & 0x8000u) >> 15u).
            arg((ntohs(raw->flags_offset) & 0x4000u) >> 14u).
            arg(ntohs(raw->flags_offset) & 0x1fffu).
            arg(raw->ttl).
            arg(PacketTypeString[ipType]).
            arg(int(ipType)).
            arg(ntohs(raw->checksum), 4, 16, QChar('0')).
            arg(sourceIP).
            arg(destinationIP);

    return info;
}

QString ImplPackets::ip::getSrc() {
    return sourceIP;
}

QString ImplPackets::ip::getDst() {
    return destinationIP;
}

ImplPackets::tcp::tcp(const u_char *data, int id, pcap_pkthdr *header, packets *next)
        : packets(data, id, packets::IP_TCP, header, next) {
    this->raw = (format *) data;
}


QString ImplPackets::tcp::getSrc() {
    if (!sourceHost.isEmpty())
        return sourceHost;

    auto next = this->getNext();
    if (next != nullptr)
        sourceHost += next->getSrc();
    sourceHost += QString(":%1").arg(ntohs(raw->sourcePort));

    return sourceHost;
}

QString ImplPackets::tcp::getDst() {
    if (!destinationHost.isEmpty())
        return destinationHost;

    auto next = this->getNext();
    if (next != nullptr)
        destinationHost += next->getDst();
    destinationHost += QString(":%1").arg(ntohs(raw->destinationPort));

    return destinationHost;
}

QString &ImplPackets::tcp::getInfo() {
    if (!info.isEmpty())
        return info;

    info += QString("===================TCP Protocol=================\n"
                    "Source Port: %1\n"
                    "Destination Port: %2\n"
                    "Sequence number: %3\n"
                    "Acknowledgment number: %4\n"
                    "Header Length: %5\n"
                    "Flags: %6 %7\n"
                    "Windows Size: %8\n"
                    "Checksum: %9\n"
                    "Urgent Pointer: %10\n").
            arg(ntohs(raw->sourcePort)).
            arg(ntohs(raw->destinationPort)).
            arg(ntohl(raw->seq)).
            arg(ntohl(raw->ack)).
            arg(raw->headerLen >> 2u).
            arg(int(raw->flags), 3, 16, QChar('0')).
            arg(flagString[raw->flags & 0xffu]).
            arg(ntohs(raw->windows)).
            arg(ntohs(raw->checksum), 4, 16, QChar('0')).
            arg(ntohs(raw->urgentPointer));

    return info;
}

ImplPackets::udp::udp(const u_char *data, int id, pcap_pkthdr *header, packets *next)
        : packets(data, id, packets::IP_UDP, header, next) {
    this->raw = (format *) data;
}

QString ImplPackets::udp::getSrc() {
    if (!sourceHost.isEmpty())
        return sourceHost;

    auto next = this->getNext();
    if (next != nullptr)
        sourceHost += next->getSrc();
    sourceHost += QString(":%1").arg(ntohs(raw->sourcePort));

    return sourceHost;
}

QString ImplPackets::udp::getDst() {
    if (!destinationHost.isEmpty())
        return destinationHost;

    auto next = this->getNext();
    if (next != nullptr)
        destinationHost += next->getDst();
    destinationHost += QString(":%1").arg(ntohs(raw->destinationPort));

    return destinationHost;
}

QString &ImplPackets::udp::getInfo() {
    if (!info.isEmpty())
        return info;

    info += QString("===================UDP Protocol=================\n"
                    "Source Port: %1\n"
                    "Destination Port: %2\n"
                    "DataLen: %3\n"
                    "Checksum: %4\n").
            arg(ntohs(raw->sourcePort)).
            arg(ntohs(raw->destinationPort)).
            arg(ntohs(raw->len)).
            arg(ntohs(raw->checksum), 4, 16, QChar('0'));

    return info;
}

ImplPackets::icmp::icmp(const u_char *data, int id, pcap_pkthdr *header, packets *next)
        : packets(data, id, IP_ICMP, header, next) {
    this->raw = (format *) data;
}

QString &ImplPackets::icmp::getInfo() {
    if (!info.isEmpty())
        return info;

    auto type = "";
    switch (raw->type) {
        case 8:
            type = "request";
            break;
        case 0:
            type = "reply";
            break;
        default:
            type = "";
    }


    info += QString("==================ICMP Protocol=================\n"
                    "Type: %1 (%2)\n"
                    "Code: %3\n"
                    "Checksum: %4\n"
                    "Identification: %5\n"
                    "Sequence: %6\n").
            arg(raw->type).
            arg(type).
            arg(raw->code).
            arg(ntohs(raw->checksum), 4, 16, QChar('0')).
            arg(ntohs(raw->identification), 4, 16, QChar('0')).
            arg(ntohs(raw->seq), 4, 16, QChar('0'));

    return info;
}

ImplPackets::arp::arp(const u_char *data, int id, pcap_pkthdr *header, packets *next)
        : packets(data, id, packets::ETH_ARP, header, next) {
    this->raw = (format *) data;

}

QString ImplPackets::arp::getSrc() {
    return packets::getSrc();
}

QString ImplPackets::arp::getDst() {
    return packets::getDst();
}

QString &ImplPackets::arp::getInfo() {
    if (!info.isEmpty())
        return info;

    info += QString("==================ARP Protocol==================\n"
                    "Hardware Type: %1 (%2)\n"
                    "Protocol Type: %3 (%4)\n"
                    "Hardware Length: %5\n"
                    "Protocol Length: %6\n"
                    "Operation Code: ").
            arg(ntohs(raw->hardwareType) == 1 ? "Ethernet" : "").
            arg(ntohs(raw->hardwareType)).
            arg(packets::PacketTypeString[packets::PacketType(ntohs(raw->protocolType))]).
            arg(ntohs(raw->protocolType), 4, 16, QChar('0')).
            arg(ntohs(raw->hardwareLen)).
            arg(ntohs(raw->protocolLen));

    auto op = ntohs(raw->operationCode);
    switch (op) {
        case 1:
            info += QString("%1 (%2)\n").arg("request").arg(op);
            break;
        case 2:
            info += QString("%1 (%2)\n").arg("reply").arg(op);
            break;
        default:
            info += QString("Unknown operation code (%1)").arg(op);
    }

    return info;
}

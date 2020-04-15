//
// Created by 76971 on 2020/3/22.
//

#ifndef USNIFFER_PACKETS_H
#define USNIFFER_PACKETS_H

#include <iostream>
#include <unordered_map>
#include <QString>
#include "pcap.h"

class packets {
public:
    enum PacketType {
        None,
        ETH,
        ETH_IP = 0x0800,
        ETH_ARP = 0x0806,
        ETH_RARP = 0x0835,
        IP_TCP = 0x06,
        IP_UDP = 0x11,
        IP_ICMP = 0x01,
    };
    std::unordered_map<PacketType, const char *> PacketTypeString = {
            {None,     "None"},
            {ETH,      "Ethernet"},
            {ETH_IP,   "IP"},
            {ETH_ARP,  "ARP"},
            {ETH_RARP, "RARP"},
            {IP_TCP,   "TCP"},
            {IP_UDP,   "UDP"},
            {IP_ICMP,  "ICMP"},
    };
private:
    const u_char *data;
    packets *next;
    int id;
    pcap_pkthdr *header;
    PacketType packetType;
    QString time{};
    QString empty{};
    QString hex{};
public:

    packets(const u_char *data, int id, PacketType type, pcap_pkthdr *header, packets *next = nullptr);

    int getId() const;

    packets *getNext() const;

    pcap_pkthdr *getHeader() const;

    int getPacketLen();

    QString &getTime();

    QString getType();

    virtual QString getSrc();

    virtual QString getDst();

    virtual QString &getInfo();

    virtual QString &getHex();

    virtual packets *getPackets();

    virtual ~packets();

public:
    static packets *MakePackets(int id, const u_char *data, const pcap_pkthdr *header);

};

namespace ImplPackets {

    class eth : public packets {
    public:
        typedef struct {
            u_char destinationHost[6];
            u_char sourceHost[6];
            u_short type;
        } format;
    private:
        format *raw;
        QString info{};
        PacketType ethType{};
    public:
        eth(const u_char *data, int id, pcap_pkthdr *header, packets *next = nullptr);

        const u_char *getEthData() const;

        packets *getPackets() override;

        QString &getInfo() override;

        QString getSrc() override;

        QString getDst() override;

    };

    class ip : public packets {
    public:
        typedef struct {
            u_char version_headerLen;
            u_char tos;
            u_short len;
            u_short identification;
            u_short flags_offset;
            u_char ttl;
            u_char protocol;
            u_short checksum;
            u_int sourceAddr;
            u_int destinationAddr;
        } format;
    private:
        format *raw;
        PacketType ipType{};
        QString sourceIP{};
        QString destinationIP{};
        QString info{};
    public:
        ip(const u_char *data, int id, pcap_pkthdr *header, packets *next = nullptr);

        const u_char *getIpData() const;

        packets *getPackets() override;

        QString &getInfo() override;

        QString getSrc() override;

        QString getDst() override;
    };

    class tcp : public packets {
    public:
        typedef struct {
            u_short sourcePort;
            u_short destinationPort;
            u_int seq;
            u_int ack;
            u_char headerLen;
            u_char flags;
            u_short windows;
            u_short checksum;
            u_short urgentPointer;
        } format;
    private:
        format *raw;
        QString sourceHost{};
        QString destinationHost{};
        QString info{};
        std::unordered_map<char, const char *> flagString = {
                {0x08, "(PSH)"},
                {0x10, "(ACK)"},
                {0x02, "(SYN)"},
                {0x20, "(URG)"},
                {0x01, "(FIN)"},
                {0x04, "(RST)"},
        };
    public:
        tcp(const u_char *data, int id, pcap_pkthdr *header, packets *next = nullptr);

        QString &getInfo() override;

        QString getSrc() override;

        QString getDst() override;
    };

    class udp : public packets {
    public:
        typedef struct {
            u_short sourcePort;
            u_short destinationPort;
            u_short len;
            u_short checksum;
        } format;
    private:
        format *raw;
        QString sourceHost{};
        QString destinationHost{};
        QString info{};
    public:
        udp(const u_char *data, int id, pcap_pkthdr *header, packets *next = nullptr);

        QString getSrc() override;

        QString getDst() override;

        QString &getInfo() override;

    };

    class icmp : public packets {
    public:
        typedef struct {
            u_char type;
            u_char code;
            u_short checksum;
            u_short identification;
            u_short seq;
        } format;
    private:
        format *raw;
        QString info{};
    public:
        icmp(const u_char *data, int id, pcap_pkthdr *header, packets *next = nullptr);

        QString &getInfo() override;
    };

    class arp : public packets {
    public:
        typedef struct {
            u_short hardwareType;
            u_short protocolType;
            u_char hardwareLen;
            u_char protocolLen;
            u_short operationCode;
            u_char sourceMac[6];
            u_char sourceIp[4];
            u_char destinationMac[6];
            u_char destinationIp[4];
        } format;
    private:
        format *raw;
        QString info{};
    public:
        arp(const u_char *data, int id, pcap_pkthdr *header, packets *next = nullptr);

        QString getSrc() override;

        QString getDst() override;

        QString &getInfo() override;

    };

    class igmp : public packets {
    };

    class rarp : public packets {
    };
}

#endif //USNIFFER_PACKETS_H

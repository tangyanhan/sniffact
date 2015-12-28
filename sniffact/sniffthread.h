#ifndef LISTENTHREAD_H
#define LISTENTHREAD_H

#include <QThread>
#include <QMutex>
#include "common.h"
#include "packet.h"

#include "sniffsettings.h"

class SniffThread : public QThread
{
    Q_OBJECT
public:
    SniffThread();
    void run();
    void initSniff(QString adapterName,int promisc,QString filterString);
    void initSniff(QString fileName); //init offline sniff
    void initSniff(const SniffSettings* settings);
    void initDumper();
    void stop();
private:
    volatile bool stopped;
    pcap_t *adapter;
    pcap_dumper_t *dumper;
    QMutex mutex;
signals:
    void signalPacketReceived(Packet*);
    void error(QString message);
};

#endif // LISTENTHREAD_H

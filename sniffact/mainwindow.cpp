#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "packetbuffer.h"
#include "tempfile.h"
#include "luasettings.h"

#include <QMessageBox>
#include <QLibraryInfo>
#include <QCloseEvent>
#include <QFileDialog>


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    createModel();
    sniffSetDialog =new SniffSetDialog(this);
    sniffSetDialog->show();
    sniffThread =new SniffThread;
    luaThread =new LuaThread;

    connect(sniffSetDialog,SIGNAL(accepted()),
            this,SLOT(slotSniffSetDialogAccepted()));

    connect(luaThread,SIGNAL(signalLuaResult(QString)),
            this,SLOT(displayLuaResult(QString)));

    connect(sniffThread,SIGNAL(signalPacketReceived(Packet*)),
            luaThread,SLOT(slotPacketReceived(Packet*)));

    connect(sniffThread,SIGNAL(signalPacketReceived(Packet*)),
            this,SLOT(slotPacketReceived(Packet*)));

    connect(sniffThread,SIGNAL(error(QString)),
            this,SLOT(echoOnSniffThreadError(QString)));

    ui->sniffState->setText(tr("Stopped"));
}

MainWindow::~MainWindow()
{
    sniffThread->deleteLater();
    luaThread->deleteLater();
    delete ui;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if(sniffThread->isRunning()) {
        int ret=QMessageBox::information(this,tr("Hint"),
                                 tr("A sniffer process is running.Would you like to abort it？"),
                                 QMessageBox::Yes|QMessageBox::Cancel);
        if(ret==QMessageBox::Cancel)
            return;
        else if(ret==QMessageBox::Yes){
            sniffThread->stop();
            sniffThread->wait();
            luaThread->stop();
            luaThread->wait();
            ui->luaState->setText(tr("Inactive"));
        }
    }
    event->accept();
}

void MainWindow::createModel()
{
    model = new QStandardItemModel(0, 6, this);

    model->setHeaderData(0, Qt::Horizontal, QObject::tr("No. "));
    model->setHeaderData(1, Qt::Horizontal, QObject::tr("Time"));
    model->setHeaderData(2, Qt::Horizontal, QObject::tr("Length"));
    model->setHeaderData(3, Qt::Horizontal, QObject::tr("Dst Address"));
    model->setHeaderData(4, Qt::Horizontal, QObject::tr("Src Address"));
    model->setHeaderData(5, Qt::Horizontal, QObject::tr("Protocol"));
    ui->packetView->setModel(model);
    ui->packetView->setColumnWidth(0,50);
    ui->packetView->setColumnWidth(1,80);
    ui->packetView->setColumnWidth(2,60);
    ui->packetView->setColumnWidth(3,150);
    ui->packetView->setColumnWidth(4,150);
    ui->packetView->setColumnWidth(5,60);
}

/*Insert the newly received packet into treeview.
 *Information about the raw packet are derived by
 *constructing a Packet, so it will be done automatically.
 */
void MainWindow::slotPacketReceived(Packet *packet)
{
    int index =model->rowCount();
    model->insertRow(index);
    if(!firstPacketTime) {//If offline capture,get the timestamp of the first packet as start.
        firstPacketTime =packet->getTime();
    }
    char arriveTime[100];
    sprintf(arriveTime,"%.3f",(packet->getTime()-firstPacketTime));

    //GUI operations

    //Model structure：No.,Time,Length,Dst Addr,Src Addr,Protocol
    model->setData(model->index(index,0),index);
    model->setData(model->index(index,1),arriveTime);
    model->setData(model->index(index,2),(int)packet->getDataLength());
    model->setData(model->index(index,3),(QString)packet->getDstAddr());
    model->setData(model->index(index,4),(QString)packet->getSrcAddr());
    model->setData(model->index(index,5),packet->getProtocolName());
    statusBar()->showMessage(tr("%1 packets received").arg(index+1));
}

void MainWindow::handleRunningSniff()
{
    if(sniffThread->isRunning()){
        int ret=QMessageBox::information(this,tr("Hint"),
                                 tr("A sniffer process is running.Would you like to abort it？"),
                                 QMessageBox::Yes|QMessageBox::Cancel);
        if(ret==QMessageBox::Cancel)
            return;
        else if(ret==QMessageBox::Yes){
            sniffThread->stop();
            sniffThread->wait();
        }
    }
    model->removeRows(0,model->rowCount());
}

void MainWindow::startSniff(SniffSettings *settings)
{
    try{
        handleRunningSniff();
        sniffThread->initSniff(settings);
        sniffThread->start();
        nPacketsReceived =0;
        firstPacketTime  =0;
        ui->sniffState->setText(tr("Interface: %1|Mode:%2")
                                 .arg(settings->adapterName).arg(settings->promiscous));
    }catch(InvalidSettingsException &e) {
        QMessageBox::critical(this,tr("Invalid Settings"),e.what(),QMessageBox::Ok);
        return;
    }catch(Exception &e) {
        QMessageBox::critical(this,tr("Error"),e.what(),QMessageBox::Ok);
        return;
    }
}

void MainWindow::startSniff(QString fileName)
{
    try{
        handleRunningSniff();
        sniffThread->initSniff(fileName);
        sniffThread->start();
        nPacketsReceived =0;
        firstPacketTime =0;
        ui->sniffState->setText(tr("File:%1").arg(fileName));
    }catch(InvalidSettingsException &e) {
        QMessageBox::critical(this,tr("Invalid Settings"),e.what(),QMessageBox::Ok);
        return;
    }catch(Exception &e) {
        QMessageBox::critical(this,tr("Error"),e.what(),QMessageBox::Ok);
        return;
    }
}

void MainWindow::slotSniffSetDialogAccepted() {
    try{
        sniffSetDialog->check();
        startSniff(sniffSetDialog);
    }catch(InvalidSettingsException e) {
        QMessageBox::critical(this,tr("Error"),e.what(),QMessageBox::Ok);
        return;
    }
}

void MainWindow::slotLuaSetDialogAccepted() {
    try{
        startLuaThread();
    }catch(InvalidSettingsException e) {
        QMessageBox::critical(this,tr("Error"),e.what(),QMessageBox::Ok);
        return;
    }
}


void MainWindow::on_setAction_triggered()
{
    sniffSetDialog->show();
}

void MainWindow::on_beginAction_triggered() {
    startSniff(sniffSetDialog);
}


//If an error occurs, it means the data received is no longer
//reliable, so we have to clean the corrosponding data in GUI for safe.
void MainWindow::echoOnSniffThreadError(QString message)
{
    QMessageBox::critical(this,tr("Error while sniffing"),message);
    model->removeRows(0,model->rowCount());
    stopSniff();
}

void MainWindow::displayLuaResult(QString result)
{
    if(!result.isEmpty())
        ui->luaResult->append(result);
}

void MainWindow::stopSniff()
{
    if(sniffThread->isRunning()) {
        sniffThread->stop();
        sniffThread->wait();
        ui->sniffState->setText(tr("Stopped"));
    }
}

/** Start a Lua Thread.Note that there must be a sniffThread running,or else
  * the luaThread will die for starvation.
  */
void MainWindow::startLuaThread()
{
    if(!sniffThread->isRunning()) {
        QMessageBox::information(this,tr("Error"),tr("Please start a sniff process first"));
        return;
    }

    if(luaThread->isRunning()){
        int ret =QMessageBox::information(this,tr("Warning"),
                                          tr("One action is running.This operation will abort the old one.\n"
                                             "Would you like to continue?"),
                                          QMessageBox::Yes|QMessageBox::Cancel);
        if(ret ==QMessageBox::Cancel)
            return;
        else{
            luaThread->stop();
            luaThread->wait();
        }
    }
    try{
        QString fileName =ui->scriptPath->text();
        QString functionName =ui->functionName->text();
        LuaSettings settings(fileName,functionName);
        luaThread->init(settings);
        luaThread->start();
        ui->luaState->setText(tr("Running"));
    }catch(InvalidSettingsException &e) {
        QMessageBox::warning(this,tr("Warning"),e.what(),QMessageBox::Ok);
    }
}

void MainWindow::on_stopAction_triggered()
{
    stopSniff();
}


void MainWindow::on_packetView_pressed(QModelIndex index)
{
    try{
        PacketBuffer * packetBuffer =PacketBuffer::getInstance();

        Packet *packet =packetBuffer->getPacket(index.row());

        ui->asciiPacket->setText(QString::fromStdString(packet->toAsciiString()));
        ui->hexPacket->setText(QString::fromStdString(packet->toHexString()));
    }catch(Exception &e) {
        QMessageBox::critical(this,tr("Error"),e.what(),QMessageBox::Ok);
    }
}

void MainWindow::on_quitAction_triggered()
{
    this->close();
}

void MainWindow::on_browse_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
                                                    tr("Import LUA Script"), ".", tr("LUA Scripts(*.lua)"));
    ui->scriptPath->setText(fileName);
}

void MainWindow::on_startScript_clicked() {
    startLuaThread();
}

void MainWindow::on_stopScript_clicked() {
    stopLuaThread();
}

void MainWindow::stopLuaThread()
{
    luaThread->stop();
    luaThread->wait();
    ui->luaState->setText(tr("Inactive"));
}

void MainWindow::on_clearScriptOutput_clicked()
{
    ui->luaResult->clear();
}

void MainWindow::on_helpAction_triggered()
{
    QMessageBox::about(this,tr("How to use sniffact"),
                       tr("Sniffact is a program that provides Lua interface, you can use your own lua scripts to extend this program.\
For more information,refer to the help document."));
}

void MainWindow::on_aboutAuthor_triggered()
{
    QMessageBox::about(this,tr("About the author"),tr("Donald <tang_yanhan@126.com>\n\
Related works(by 2011.9): \n\
Speedlink: code.google.com/p/speedlink\n\
Sniffact : code.google.com/p/sniffact\n\
Linkapp for 802.1x linkage authention: http://code.google.com/p/linkapp-for-linkage-authentication\n\
Contact me if you have any problems with my program."));
}

void MainWindow::on_aboutProgram_triggered()
{
    QMessageBox::about(this,tr("About the author"),tr("Sniffact 1.0 by Donald <tang_yanhan@126.com>\n")+QLibraryInfo::licensee());
}

void MainWindow::on_openFileAction_triggered()
{
   QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"),
                                                 ".",
                                                 tr("Pcap Capture File (*.pcap)"));
   if(!fileName.isEmpty())
       startSniff(fileName);
}


void MainWindow::on_saveFileAction_triggered()
{
    if(sniffThread->isRunning()) {
        QMessageBox::information(this,tr("Information"),tr("Please stop the sniffer first"),QMessageBox::Ok);
        return;
    }

    try{
        QString fileName =QFileDialog::getSaveFileName(this,
                                                       tr("Save File"),
                                                       ".",
                                                       tr("Pcap Capture File (*.pcap)"));

        if(!fileName.isEmpty()) {
            TempFile *tmpFile =TempFile::getInstance();
            tmpFile->saveFile(fileName);
        }
    }catch(TempFileException &e) {
        QMessageBox::critical(this,"Error",
                              "Error while saving file: %1"+e.what(),
                              QMessageBox::Ok);
    }
}

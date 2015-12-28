#include "sniffsetdialog.h"
#include "ui_sniffsetdialog.h"
#include <QMessageBox>
#include <QTextStream>

SniffSetDialog::SniffSetDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SniffSetDialog)
{
    ui->setupUi(this);
    loadDeviceList();
}

SniffSetDialog::~SniffSetDialog()
{
    delete ui;
}

/** Find out all network devices in the system and list them in a combox.
  * In the combox,Displays a valid name and set the corrosponding data as the name.
  * Under systems such as linux,network connections will not have a description and
  * their names are human-readable. Yet for Windows platform,the name is a nightmare
  * and description is needed.
  */
void SniffSetDialog::loadDeviceList()
{
    pcap_if_t *alldevs;
    int nDevice; //Total number of network connections available.
    char errBuf[PCAP_ERRBUF_SIZE];
    adapterName.clear();

    if(pcap_findalldevs(&alldevs,errBuf)!=0){
        int ret=QMessageBox::critical(this,tr("Error"),tr("Unable to get device list:%1").arg(errBuf),QMessageBox::Ok);
        if(ret==QMessageBox::Ok)
            this->hide();
        return;
    }

    pcap_if *d;
    for(nDevice=0,d=alldevs;d;d=d->next){
        //qDebug()<<d->name<<"   "<<d->description<<endl;
        //For linux platforms.
        QString devString =QString::fromAscii(d->name);
        /* For Windows only */
        if(devString.isEmpty())
            devString =QString::fromAscii(d->description);
        if(devString.contains("usb",Qt::CaseInsensitive))
            continue;
        ++nDevice;
        ui->deviceList->insertItem(0,devString,devString);
    }
    pcap_freealldevs(alldevs);
    if(nDevice){
        adapterName=ui->deviceList->itemData(ui->deviceList->currentIndex()).toString();
        ui->adapterHint->setText(tr("One or more device detected on your computer.\nSelect one to sniff"));
    }else{
        ui->adapterHint->setText(tr("No device available"));
        int ret=QMessageBox::critical(this,tr("No device"),
        tr("No device available.Device disabled or no access permisson(Under linux systems root maybe required)"),
        QMessageBox::Ok);
        if(ret==QMessageBox::Ok)
            this->hide();
    }
}

void SniffSetDialog::on_deviceList_currentIndexChanged(int index)
{
    adapterName=ui->deviceList->itemData(index).toString();
}

void SniffSetDialog::on_ok_clicked()
{
    filterString=ui->pcapFilterString->text();
    promiscous=ui->promiscuous->isChecked();
    emit accepted();
    this->hide();
}


void SniffSetDialog::on_cancel_clicked()
{
    emit rejected();
    this->hide();
}

void SniffSetDialog::closeEvent(QCloseEvent *)
{
    this->hide();
}

void SniffSetDialog::on_loadScript_clicked()
{
    emit invokeLoadScriptDialog();
}

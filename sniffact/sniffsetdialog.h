#ifndef SNIFFSETDIALOG_H
#define SNIFFSETDIALOG_H

#include <QDialog>
#include "common.h"
#include "sniffsettings.h"

namespace Ui {
    class SniffSetDialog;
}

class SniffSetDialog : public QDialog,public SniffSettings
{
    Q_OBJECT
public:
    explicit SniffSetDialog(QWidget *parent = 0);
    ~SniffSetDialog();
    void loadDeviceList();
protected:
    void closeEvent(QCloseEvent *);
private:
    Ui::SniffSetDialog *ui;
signals:
    void invokeLoadScriptDialog();
private slots:
    void on_cancel_clicked();
    void on_ok_clicked();
    void on_deviceList_currentIndexChanged(int index);
    void on_loadScript_clicked();
};

#endif // SNIFFSETDIALOG_H

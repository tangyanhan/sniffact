#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include "sniffsetdialog.h"
#include "sniffthread.h"
#include "luathread.h"
#include "common.h"
#include "packet.h"
#include <QVector>
#include <QMutex>

QT_BEGIN_NAMESPACE
class QAbstractItemModel;
class QCheckBox;
class QComboBox;
class QGroupBox;
class QLabel;
class QLineEdit;
class QSortFilterProxyModel;
class QTreeView;
class QCloseEvent;
QT_END_NAMESPACE


namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    void startSniff(SniffSettings*); //Online Sniff
    void startSniff(QString fileName);//Offline Sniff
    void stopSniff();
    void handleRunningSniff();

    void startLuaThread();
    void stopLuaThread();

    void createModel();
    SniffThread *sniffThread;
    LuaThread *luaThread;
    SniffSetDialog *sniffSetDialog;
    QStandardItemModel *model;
    Ui::MainWindow *ui;
    QMutex mutex;
    int nPacketsReceived;
    qreal firstPacketTime; //arrive time of the first packet.
protected:
    virtual void closeEvent(QCloseEvent *);
public slots:
    void slotPacketReceived(Packet*);
    void echoOnSniffThreadError(QString message);
    void displayLuaResult(QString);
private slots:
    void slotSniffSetDialogAccepted();
    void slotLuaSetDialogAccepted();
    void on_packetView_pressed(QModelIndex index);
    void on_stopAction_triggered();
    void on_beginAction_triggered();
    void on_setAction_triggered();
    void on_quitAction_triggered();
    void on_browse_clicked();
    void on_startScript_clicked();
    void on_stopScript_clicked();
    void on_clearScriptOutput_clicked();
    void on_helpAction_triggered();
    void on_aboutAuthor_triggered();
    void on_aboutProgram_triggered();
    void on_openFileAction_triggered();
    void on_saveFileAction_triggered();
};

#endif // MAINWINDOW_H

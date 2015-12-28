#-------------------------------------------------
#
# Project created by QtCreator 2011-04-28T19:53:17
#
#-------------------------------------------------

QT       += core gui

TARGET = sniffact
TEMPLATE = app

LIBS += -lpcap -lnet -llua5.1

FORMS += \
    mainwindow.ui \
    sniffsetdialog.ui

RESOURCES += \
    resources.qrc

HEADERS += \
    sniffthread.h \
    sniffsetdialog.h \
    packetpool.h \
    packet.h \
    mainwindow.h \
    luathread.h \
    lua_interface.h \
    common.h \
    settings.h \
    sniffsettings.h \
    luasettings.h \
    header.h \
    packetbuffer.h \
    tempfile.h


SOURCES += \
    sniffthread.cpp \
    sniffsetdialog.cpp \
    packetpool.cpp\
    packet.cpp \
    mainwindow.cpp \
    main.cpp \
    luathread.cpp \
    lua_interface.cpp \
    header.cpp \
    packetbuffer.cpp \
    tempfile.cpp


#Translations
TRANSLATIONS = hans_simplified.ts











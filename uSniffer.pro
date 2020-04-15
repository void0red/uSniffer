QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11 release static

QMAKE_CXXFLAGS_RELEASE += -O3 -mthreads

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    view.cpp \
    DeviceWindow.cpp \
    controller.cpp \
    packets.cpp \

HEADERS += \
    controller.h \
    DeviceWindow.h \
    packets.h \
    view.h \

FORMS += \
    view.ui \
    device.ui \

win32: LIBS += -L$$PWD/WpdPack/Lib/x64/ -lwpcap -lws2_32

INCLUDEPATH += $$PWD/WpdPack/Include
DEPENDPATH += $$PWD/WpdPack/Lib/x64

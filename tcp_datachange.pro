TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        data_cg.cpp \
        main.cpp \
        util.cpp

HEADERS += \
    data_cg.h \
    key.h \
    sfdafx.h \
    util.h

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../../../usr/local/lib/release/ -lnfnetlink
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../../../usr/local/lib/debug/ -lnfnetlink
else:unix: LIBS += -L$$PWD/../../../../usr/local/lib/ -lnfnetlink

LIBS += -lnetfilter_queue

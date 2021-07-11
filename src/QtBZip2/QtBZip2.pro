NAME         = QtBZip2
TARGET       = $${NAME}
QT           = core
QT          -= gui

load(qt_build_config)
load(qt_module)

INCLUDEPATH += $${PWD}

HEADERS     += $${PWD}/qtbzip2.h

SOURCES     += $${PWD}/qtbzip2.cpp

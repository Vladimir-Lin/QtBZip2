NAME         = QtBZip2
TARGET       = $${NAME}
QT           = core
QT          -= gui
CONFIG(static,static|shared) {
# static version does not support Qt Script now
QT          -= script
} else {
QT          += script
}

load(qt_build_config)
load(qt_module)

INCLUDEPATH += $${PWD}/../../include/QtBZip2

HEADERS     += $${PWD}/../../include/QtBZip2/QtBZip2
HEADERS     += $${PWD}/../../include/QtBZip2/qtbzip2.h

SOURCES     += $${PWD}/qtbzip2.cpp
SOURCES     += $${PWD}/ScriptableBZip2.cpp

OTHER_FILES += $${PWD}/../../include/$${NAME}/headers.pri

include ($${PWD}/../../doc/Qt/Qt.pri)

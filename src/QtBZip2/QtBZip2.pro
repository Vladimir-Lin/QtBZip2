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

INCLUDEPATH += $${PWD}

HEADERS     += $${PWD}/qtbzip2.h

SOURCES     += $${PWD}/qtbzip2.cpp
SOURCES     += $${PWD}/ScriptableBZip2.cpp

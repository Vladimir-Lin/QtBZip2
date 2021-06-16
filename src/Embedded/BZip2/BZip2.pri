INCLUDEPATH += $${PWD}

HEADERS     += $${PWD}/qtlzo.h

SOURCES     += $${PWD}/qtlzo.cpp
SOURCES     += $${PWD}/ScriptableLzo.cpp

CONFIG(debug, debug|release) {
LIBS        += -llzo2d
} else {
LIBS        += -llzo2
}

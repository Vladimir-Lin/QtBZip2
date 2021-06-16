QT             = core
QT            -= gui
QT            += QtBZip2

CONFIG(debug, debug|release) {
TARGET         = bzip2toold
} else {
TARGET         = bzip2tool
}

CONFIG        += console

TEMPLATE       = app

SOURCES       += $${PWD}/bzip2tool.cpp

win32 {
RC_FILE        = $${PWD}/bzip2tool.rc
OTHER_FILES   += $${PWD}/bzip2tool.rc
OTHER_FILES   += $${PWD}/*.js
}

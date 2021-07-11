load(configure)
load(qt_parts)

OTHER_FILES += $${PWD}/*.bat
OTHER_FILES += $${PWD}/.qmake.conf
OTHER_FILES += $${PWD}/sync.profile
OTHER_FILES += $${PWD}/*.md

include ($${PWD}/doc/Qt/Qt.pri)

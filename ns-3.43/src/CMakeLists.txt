build_lib(
    LIBNAME aodv
    SOURCE_FILES
        helper/aodv-helper.cc
        model/aodv-routing-protocol.cc
        model/aodv-rtable.cc
        model/aodv-rqueue.cc
        model/aodv-packet.cc
        model/aodv-neighbor.cc
        model/aodv-dpd.cc
        model/aodv-id-cache.cc
        model/aodv-neighbor-etx.cc  # <--- TAMBAHKAN BARIS INI
    HEADER_FILES
        helper/aodv-helper.h
        model/aodv-routing-protocol.h
        model/aodv-rtable.h
        model/aodv-rqueue.h
        model/aodv-packet.h
        model/aodv-neighbor.h
        model/aodv-dpd.h
        model/aodv-id-cache.h
        model/aodv-neighbor-etx.h   # <--- TAMBAHKAN BARIS INI
    LIBRARIES_TO_LINK
        ${libinternet}
        ${libwifi}
    TEST_SOURCES
        test/aodv-id-cache-test-suite.cc
        test/aodv-regression.cc
        test/aodv-test-suite.cc
        test/bug-772.cc
        test/loopback.cc
)

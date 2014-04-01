include(ExternalProject)
ExternalProject_Add(
    odb
    PREFIX ${CMAKE_BINARY_DIR}/odb
    URL http://www.codesynthesis.com/download/odb/2.2/odb-2.2.2.tar.gz
    URL_HASH SHA1=f461e28658ed9546d95efaa8d25f92f59b895311
    TIMEOUT 600
    CONFIGURE_COMMAND ${CMAKE_BINARY_DIR}/odb/src/odb/configure --prefix=<INSTALL_DIR>
    BUILD_COMMAND ${MAKE}
    )



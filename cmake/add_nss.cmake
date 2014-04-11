# Set up build steps
include(ExternalProject)
ExternalProject_Add(
    openssl
    URL http://www.openssl.org/source/openssl-1.0.1g.tar.gz   
    URL_HASH MD5=de62b43dfcd858e66a74bee1c834e959
    TIMEOUT 600
    CONFIGURE_COMMAND ./Configure --prefix=<SOURCE_DIR>/openssl linux-x86_64
    BUILD_COMMAND make
    BUILD_IN_SOURCE ON
    INSTALL_COMMAND make install
    )
ExternalProject_Get_Property(openssl source_dir)
include_directories(SYSTEM ${source_dir}/openssl/include)
include_directories(SYSTEM ${source_dir})
link_directories(SYSTEM ${source_dir}/openssl/lib)




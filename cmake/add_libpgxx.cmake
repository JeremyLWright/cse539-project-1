include(ExternalProject)
ExternalProject_Add(
    libpgxx
    URL http://pqxx.org/download/software/libpqxx/libpqxx-4.0.1.tar.gz
    URL_HASH SHA1=4748835bd1a90fb34e6e577788006a416c2acb60
    TIMEOUT 600
    #PATCH_COMMAND ${CMAKE_COMMAND} -E copy
    #    ${CMAKE_SOURCE_DIR}/src/third_party_libs/${BoostFolderName}/boost_variant_detail_move_patched.hpp
    #    <SOURCE_DIR>/boost/variant/detail/move.hpp
    CONFIGURE_COMMAND  <SOURCE_DIR>/configure --prefix=<INSTALL_DIR>
    BUILD_COMMAND make
    #BUILD_IN_SOURCE ON
    #INSTALL_COMMAND ""
    #LOG_DOWNLOAD ON
    #LOG_UPDATE ON
    #LOG_CONFIGURE ON
    #LOG_BUILD ON
    #LOG_TEST ON
    #LOG_INSTALL ON
    )

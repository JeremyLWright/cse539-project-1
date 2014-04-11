include(ExternalProject)
ExternalProject_Add(
    Cryptopp
    URL http://www.cryptopp.com/cryptopp562.zip
    URL_HASH SHA1=ddc18ae41c2c940317cd6efe81871686846fa293    
    TIMEOUT 600
    #PATCH_COMMAND ${CMAKE_COMMAND} -E copy
    #    ${CMAKE_SOURCE_DIR}/src/third_party_libs/${BoostFolderName}/boost_variant_detail_move_patched.hpp
    #    <SOURCE_DIR>/boost/variant/detail/move.hpp
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make
    BUILD_IN_SOURCE ON
    INSTALL_COMMAND ""
    #LOG_DOWNLOAD ON
    #LOG_UPDATE ON
    #LOG_CONFIGURE ON
    #LOG_BUILD ON
    #LOG_TEST ON
    #LOG_INSTALL ON
    )

ExternalProject_Get_Property( Cryptopp source_dir )
# Now, set the include and linker paths.
set( CryptoPP_INCLUDE_DIR ${source_dir} )
set( CryptoPP_LIBRARY ${source_dir}/libcryptopp.a )


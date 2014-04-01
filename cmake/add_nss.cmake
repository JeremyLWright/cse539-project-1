# Set up build steps
include(ExternalProject)
ExternalProject_Add(
    nss
    URL ftp://ftp.mozilla.org/pub/mozilla.org/security/nss/releases/NSS_3_16_RTM/src/nss-3.16-with-nspr-4.10.4.tar.gz   
    URL_HASH SHA1=8ae6ddec43556b4deb949dc889123ff1d09ab737
    TIMEOUT 600
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make -C <SOURCE_DIR>/nss BUILD_OPT=1 USE_64=1 nss_build_all
    BUILD_IN_SOURCE ON
    INSTALL_COMMAND ""
    )
ExternalProject_Get_Property(nss source_dir)
set(nss_source_dir ${source_dir})
include_directories(SYSTEM "${nss_source_dir}/dist/public")

file(GLOB nss_libs_dir "${nss_source_dir}/dist/Linux*/lib/" "*.a")
file(GLOB nss_header_dir "${nss_source_dir}/dist/Linux*/include/" "*.h")
message("headers: ${nss_header_dir}")
include_directories(SYSTEM ${nss_header_dir})
file(GLOB static_nss_libs "${nss_libs_dir}" "*.a")
link_directories(SYSTEM ${static_nss_libs})




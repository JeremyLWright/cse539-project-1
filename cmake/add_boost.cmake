# Stolen from: https://github.com/maidsafe/MaidSafe/tree/master/cmake_modules
#==================================================================================================#
#                                                                                                  #
#  Copyright 2013 MaidSafe.net limited                                                             #
#                                                                                                  #
#  This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,        #
#  version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which    #
#  licence you accepted on initial access to the Software (the "Licences").                        #
#                                                                                                  #
#  By contributing code to the MaidSafe Software, or to this project generally, you agree to be    #
#  bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root        #
#  directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available   #
#  at: http://www.maidsafe.net/licenses                                                            #
#                                                                                                  #
#  Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed    #
#  under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF   #
#  ANY KIND, either express or implied.                                                            #
#                                                                                                  #
#  See the Licences for the specific language governing permissions and limitations relating to    #
#  use of the MaidSafe Software.                                                                   #
#                                                                                                  #
#==================================================================================================#
#                                                                                                  #
#  Sets up Boost using ExternalProject_Add.                                                        #
#                                                                                                  #
#  Only the first 3 variables should require regular maintenance, i.e. BoostComponents,            #
#  BoostVersion and BoostSHA1.                                                                     #
#                                                                                                  #
#  Variables set and cached by this module are:                                                    #
#    BoostSourceDir (required for subsequent include_directories calls) and per-library            #
#    variables defining the full path(s) to the release (and debug for MSVC) libraries, e.g.       #
#    BoostDateTimeLibs, BoostFilesystemLibs.                                                       #
#                                                                                                  #
#==================================================================================================#

set(BoostComponents
     atomic                   
     chrono                   
     #context                  
     #coroutine                
     date_time                
     exception                
     filesystem               
     #graph                    
     #graph_parallel           
     iostreams                
     #locale                   
     log                      
     math                     
     #mpi                      
     program_options          
     #python                   
     random                   
     regex                    
     serialization            
     #signals                  
     system                   
     test                     
     thread                   
     timer                    
     #wave 
      )
set(BoostVersion 1.55.0)
set(BoostSHA1 cef9a0cc7084b1d639e06cd3bc34e4251524c840)



# Set up general b2 (bjam) command line arguments
set(b2Args <SOURCE_DIR>/b2
           link=static
           threading=multi
           runtime-link=shared
           --layout=tagged
           --build-dir=Build
           stage
           -j8
           -d+2
           )
foreach(BoostComponent ${BoostComponents})
  list(APPEND b2Args --with-${BoostComponent})
endforeach()

# Set up platform-specific b2 (bjam) command line arguments
if(MSVC)
  list(APPEND b2Args
              toolset=msvc
#              --layout=versioned
              define=_BIND_TO_CURRENT_MFC_VERSION=1
              define=_BIND_TO_CURRENT_CRT_VERSION=1
              )
    list(APPEND b2Args address-model=64)
elseif(UNIX)
  list(APPEND b2Args variant=release cxxflags=-fPIC cxxflags=-std=c++11 -sNO_BZIP2=1) # --layout=system)
  if(${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    list(APPEND b2Args toolset=clang)
    if(HAVE_LIBC++)
      list(APPEND b2Args cxxflags=-stdlib=libc++ linkflags=-stdlib=libc++)
    endif()
  elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
    list(APPEND b2Args toolset=gcc)
  endif()
elseif(APPLE)
  list(APPEND b2Args toolset=clang cxxflags=-fPIC cxxflags=-std=c++11 architecture=combined address-model=32_64)
endif()

# Create build folder name derived from version
string(REGEX REPLACE "beta\\.([0-9])$" "beta\\1" BoostFolderName ${BoostVersion})
string(REPLACE "." "_" BoostFolderName ${BoostFolderName})
set(BoostFolderName boost_${BoostFolderName})

# Set up build steps
include(ExternalProject)
ExternalProject_Add(
    boost
    URL http://sourceforge.net/projects/boost/files/boost/${BoostVersion}/${BoostFolderName}.tar.bz2/download
    URL_HASH SHA1=${BoostSHA1}
    TIMEOUT 600
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/Build
    BUILD_COMMAND "${b2Args}"
    BUILD_IN_SOURCE ON
    INSTALL_COMMAND ""
    )

# Set extra step to build b2 (bjam)
if(MSVC)
  set(b2Bootstrap "bootstrap.bat")
else()
  set(b2Bootstrap "./bootstrap.sh")
endif()
ExternalProject_Add_Step(
    boost
    make_b2
    COMMAND ${b2Bootstrap}
    COMMENT "Building b2..."
    DEPENDEES download
    DEPENDERS configure
    WORKING_DIRECTORY <SOURCE_DIR>
    )

# Expose required variables (BoostSourceDir and library paths) to parent scope
ExternalProject_Get_Property(boost source_dir)
set(BoostSourceDir ${source_dir})
set(BoostSourceDir ${BoostSourceDir} ) #PARENT_SCOPE)
include_directories(SYSTEM "${BoostSourceDir}")
foreach(Component ${BoostComponents})
  underscores_to_camel_case(${Component} CamelCaseComponent)
  if(MSVC)
    set(Boost${CamelCaseComponent}Libs debug ${BoostSourceDir}/stage/lib/libboost_${Component}-mt-gd.lib optimized ${BoostSourceDir}/stage/lib/libboost_${Component}-mt.lib)
  else()
    set(Boost${CamelCaseComponent}Libs ${BoostSourceDir}/stage/lib/libboost_${Component}-mt.a)
  endif()
  set(Boost${CamelCaseComponent}Libs ${Boost${CamelCaseComponent}Libs} ) #PARENT_SCOPE)
endforeach()
set_target_properties(boost PROPERTIES LABELS Boost FOLDER "Third Party/Boost")


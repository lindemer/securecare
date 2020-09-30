# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/samuel/securecare/lib/mosquitto

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/samuel/securecare/lib/mosquitto

# Include any dependencies generated for this target.
include lib/cpp/CMakeFiles/mosquittopp.dir/depend.make

# Include the progress variables for this target.
include lib/cpp/CMakeFiles/mosquittopp.dir/progress.make

# Include the compile flags for this target's objects.
include lib/cpp/CMakeFiles/mosquittopp.dir/flags.make

lib/cpp/CMakeFiles/mosquittopp.dir/mosquittopp.cpp.o: lib/cpp/CMakeFiles/mosquittopp.dir/flags.make
lib/cpp/CMakeFiles/mosquittopp.dir/mosquittopp.cpp.o: lib/cpp/mosquittopp.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/samuel/securecare/lib/mosquitto/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object lib/cpp/CMakeFiles/mosquittopp.dir/mosquittopp.cpp.o"
	cd /home/samuel/securecare/lib/mosquitto/lib/cpp && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/mosquittopp.dir/mosquittopp.cpp.o -c /home/samuel/securecare/lib/mosquitto/lib/cpp/mosquittopp.cpp

lib/cpp/CMakeFiles/mosquittopp.dir/mosquittopp.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/mosquittopp.dir/mosquittopp.cpp.i"
	cd /home/samuel/securecare/lib/mosquitto/lib/cpp && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/samuel/securecare/lib/mosquitto/lib/cpp/mosquittopp.cpp > CMakeFiles/mosquittopp.dir/mosquittopp.cpp.i

lib/cpp/CMakeFiles/mosquittopp.dir/mosquittopp.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/mosquittopp.dir/mosquittopp.cpp.s"
	cd /home/samuel/securecare/lib/mosquitto/lib/cpp && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/samuel/securecare/lib/mosquitto/lib/cpp/mosquittopp.cpp -o CMakeFiles/mosquittopp.dir/mosquittopp.cpp.s

# Object files for target mosquittopp
mosquittopp_OBJECTS = \
"CMakeFiles/mosquittopp.dir/mosquittopp.cpp.o"

# External object files for target mosquittopp
mosquittopp_EXTERNAL_OBJECTS =

lib/cpp/libmosquittopp.so.1.6.12: lib/cpp/CMakeFiles/mosquittopp.dir/mosquittopp.cpp.o
lib/cpp/libmosquittopp.so.1.6.12: lib/cpp/CMakeFiles/mosquittopp.dir/build.make
lib/cpp/libmosquittopp.so.1.6.12: lib/libmosquitto.so.1.6.12
lib/cpp/libmosquittopp.so.1.6.12: /usr/lib/x86_64-linux-gnu/libssl.so
lib/cpp/libmosquittopp.so.1.6.12: /usr/lib/x86_64-linux-gnu/libcrypto.so
lib/cpp/libmosquittopp.so.1.6.12: lib/cpp/CMakeFiles/mosquittopp.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/samuel/securecare/lib/mosquitto/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared library libmosquittopp.so"
	cd /home/samuel/securecare/lib/mosquitto/lib/cpp && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/mosquittopp.dir/link.txt --verbose=$(VERBOSE)
	cd /home/samuel/securecare/lib/mosquitto/lib/cpp && $(CMAKE_COMMAND) -E cmake_symlink_library libmosquittopp.so.1.6.12 libmosquittopp.so.1 libmosquittopp.so

lib/cpp/libmosquittopp.so.1: lib/cpp/libmosquittopp.so.1.6.12
	@$(CMAKE_COMMAND) -E touch_nocreate lib/cpp/libmosquittopp.so.1

lib/cpp/libmosquittopp.so: lib/cpp/libmosquittopp.so.1.6.12
	@$(CMAKE_COMMAND) -E touch_nocreate lib/cpp/libmosquittopp.so

# Rule to build all files generated by this target.
lib/cpp/CMakeFiles/mosquittopp.dir/build: lib/cpp/libmosquittopp.so

.PHONY : lib/cpp/CMakeFiles/mosquittopp.dir/build

lib/cpp/CMakeFiles/mosquittopp.dir/clean:
	cd /home/samuel/securecare/lib/mosquitto/lib/cpp && $(CMAKE_COMMAND) -P CMakeFiles/mosquittopp.dir/cmake_clean.cmake
.PHONY : lib/cpp/CMakeFiles/mosquittopp.dir/clean

lib/cpp/CMakeFiles/mosquittopp.dir/depend:
	cd /home/samuel/securecare/lib/mosquitto && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/samuel/securecare/lib/mosquitto /home/samuel/securecare/lib/mosquitto/lib/cpp /home/samuel/securecare/lib/mosquitto /home/samuel/securecare/lib/mosquitto/lib/cpp /home/samuel/securecare/lib/mosquitto/lib/cpp/CMakeFiles/mosquittopp.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : lib/cpp/CMakeFiles/mosquittopp.dir/depend


# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


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
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/yu/YeeZ-Privacy-Computing/vendor/fflib

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build

# Include any dependencies generated for this target.
include example/sql/CMakeFiles/test_multithread.dir/depend.make

# Include the progress variables for this target.
include example/sql/CMakeFiles/test_multithread.dir/progress.make

# Include the compile flags for this target's objects.
include example/sql/CMakeFiles/test_multithread.dir/flags.make

example/sql/CMakeFiles/test_multithread.dir/test_multithread.cpp.o: example/sql/CMakeFiles/test_multithread.dir/flags.make
example/sql/CMakeFiles/test_multithread.dir/test_multithread.cpp.o: ../example/sql/test_multithread.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object example/sql/CMakeFiles/test_multithread.dir/test_multithread.cpp.o"
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_multithread.dir/test_multithread.cpp.o -c /home/yu/YeeZ-Privacy-Computing/vendor/fflib/example/sql/test_multithread.cpp

example/sql/CMakeFiles/test_multithread.dir/test_multithread.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_multithread.dir/test_multithread.cpp.i"
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yu/YeeZ-Privacy-Computing/vendor/fflib/example/sql/test_multithread.cpp > CMakeFiles/test_multithread.dir/test_multithread.cpp.i

example/sql/CMakeFiles/test_multithread.dir/test_multithread.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_multithread.dir/test_multithread.cpp.s"
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yu/YeeZ-Privacy-Computing/vendor/fflib/example/sql/test_multithread.cpp -o CMakeFiles/test_multithread.dir/test_multithread.cpp.s

# Object files for target test_multithread
test_multithread_OBJECTS = \
"CMakeFiles/test_multithread.dir/test_multithread.cpp.o"

# External object files for target test_multithread
test_multithread_EXTERNAL_OBJECTS =

../bin/test_multithread: example/sql/CMakeFiles/test_multithread.dir/test_multithread.cpp.o
../bin/test_multithread: example/sql/CMakeFiles/test_multithread.dir/build.make
../bin/test_multithread: example/sql/CMakeFiles/test_multithread.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../../../bin/test_multithread"
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_multithread.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
example/sql/CMakeFiles/test_multithread.dir/build: ../bin/test_multithread

.PHONY : example/sql/CMakeFiles/test_multithread.dir/build

example/sql/CMakeFiles/test_multithread.dir/clean:
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql && $(CMAKE_COMMAND) -P CMakeFiles/test_multithread.dir/cmake_clean.cmake
.PHONY : example/sql/CMakeFiles/test_multithread.dir/clean

example/sql/CMakeFiles/test_multithread.dir/depend:
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yu/YeeZ-Privacy-Computing/vendor/fflib /home/yu/YeeZ-Privacy-Computing/vendor/fflib/example/sql /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql/CMakeFiles/test_multithread.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : example/sql/CMakeFiles/test_multithread.dir/depend

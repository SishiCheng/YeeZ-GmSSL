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
include example/sql/CMakeFiles/ntobject.dir/depend.make

# Include the progress variables for this target.
include example/sql/CMakeFiles/ntobject.dir/progress.make

# Include the compile flags for this target's objects.
include example/sql/CMakeFiles/ntobject.dir/flags.make

example/sql/CMakeFiles/ntobject.dir/use_ntobject.cpp.o: example/sql/CMakeFiles/ntobject.dir/flags.make
example/sql/CMakeFiles/ntobject.dir/use_ntobject.cpp.o: ../example/sql/use_ntobject.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object example/sql/CMakeFiles/ntobject.dir/use_ntobject.cpp.o"
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ntobject.dir/use_ntobject.cpp.o -c /home/yu/YeeZ-Privacy-Computing/vendor/fflib/example/sql/use_ntobject.cpp

example/sql/CMakeFiles/ntobject.dir/use_ntobject.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ntobject.dir/use_ntobject.cpp.i"
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yu/YeeZ-Privacy-Computing/vendor/fflib/example/sql/use_ntobject.cpp > CMakeFiles/ntobject.dir/use_ntobject.cpp.i

example/sql/CMakeFiles/ntobject.dir/use_ntobject.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ntobject.dir/use_ntobject.cpp.s"
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yu/YeeZ-Privacy-Computing/vendor/fflib/example/sql/use_ntobject.cpp -o CMakeFiles/ntobject.dir/use_ntobject.cpp.s

# Object files for target ntobject
ntobject_OBJECTS = \
"CMakeFiles/ntobject.dir/use_ntobject.cpp.o"

# External object files for target ntobject
ntobject_EXTERNAL_OBJECTS =

../bin/ntobject: example/sql/CMakeFiles/ntobject.dir/use_ntobject.cpp.o
../bin/ntobject: example/sql/CMakeFiles/ntobject.dir/build.make
../bin/ntobject: example/sql/CMakeFiles/ntobject.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../../../bin/ntobject"
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ntobject.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
example/sql/CMakeFiles/ntobject.dir/build: ../bin/ntobject

.PHONY : example/sql/CMakeFiles/ntobject.dir/build

example/sql/CMakeFiles/ntobject.dir/clean:
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql && $(CMAKE_COMMAND) -P CMakeFiles/ntobject.dir/cmake_clean.cmake
.PHONY : example/sql/CMakeFiles/ntobject.dir/clean

example/sql/CMakeFiles/ntobject.dir/depend:
	cd /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yu/YeeZ-Privacy-Computing/vendor/fflib /home/yu/YeeZ-Privacy-Computing/vendor/fflib/example/sql /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql /home/yu/YeeZ-Privacy-Computing/vendor/fflib/build/example/sql/CMakeFiles/ntobject.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : example/sql/CMakeFiles/ntobject.dir/depend

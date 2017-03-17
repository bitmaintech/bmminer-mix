environment setup:
need 2 PATH: toolchain base path and other open source lib binary and include files base path.

for example:
XILINX_BASE_PATH=/home/XILINX/gcc-linaro-arm-linux-gnueabihf-4.7-2012.11-20121123_linux
XILINX_OTHER_LIB_BASE_PATH=/home/XILINX/bin
export XILINX_OTHER_LIB_BASE_PATH
export XILINX_BASE_PATH

How to compile:
1. set miner type value
./setminertype S9
option: S9   R4   T9   T9+

2. compile the code
make


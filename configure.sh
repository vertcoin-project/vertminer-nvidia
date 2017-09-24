# To change the cuda arch, edit Makefile.am and run ./build.sh

extracflags="-static -D_REENTRANT -falign-functions=16 -falign-jumps=16 -falign-labels=16"

CUDA_CFLAGS="-static -O3 -lineno -Xcompiler -Wall  -D_FORCE_INLINES" \
	./configure CXXFLAGS="-O3 $extracflags" --with-cuda=/usr/local/cuda --with-nvml=libnvidia-ml.so


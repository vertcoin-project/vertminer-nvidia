# allow to use Host cuda functions in C/C++
DEF_INCLUDES = @CUDA_INCLUDES@

if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST		= autogen.sh README.md README.txt LICENSE.txt \
			  vertminer.sln vertminer.vcxproj vertminer.vcxproj.filters \
			  compat/gettimeofday.c compat/getopt/getopt_long.c

SUBDIRS = compat

bin_PROGRAMS = vertminer

vertminer_SOURCES	= elist.h miner.h compat.h \
			  compat/inttypes.h compat/stdbool.h compat/unistd.h \
			  compat/sys/time.h compat/getopt/getopt.h \
			  p2pool_stats.cpp \
			  crc32.c \
			  vertminer.cpp pools.cpp util.cpp bench.cpp bignum.cpp \
			  api.cpp hashlog.cpp nvml.cpp stats.cpp sysinfos.cpp cuda.cpp \
			  Algo256/cuda_bmw256.cu Algo256/cuda_cubehash256.cu \
			  Algo256/cuda_blake256.cu Algo256/cuda_skein256.cu \
			  Algo256/blake256.cu Algo256/cuda_groestl256.cu  \
			  Algo256/bmw.cu Algo256/cuda_bmw.cu \
			  Algo256/blake2s.cu sph/blake2s.c \
			  lyra2/Lyra2.c lyra2/Sponge.c \
		          lyra2/lyra2REv2.cu lyra2/cuda_lyra2v2.cu \
			  cuda_checkhash.cu \
			  sph/bmw.c sph/blake.c sph/groestl.c sph/skein.c \
			  Algo256/cuda_keccak256.cu sph/keccak.c Algo256/keccak256.cu \
			  sph/cubehash.c sph/sha2.c
			  
if HAVE_NVML
nvml_defs = -DUSE_WRAPNVML
nvml_libs = -ldl
endif

if HAVE_WINDOWS
vertminer_SOURCES += compat/winansi.c
endif

vertminer_LDFLAGS  = $(PTHREAD_FLAGS) @CUDA_LDFLAGS@
vertminer_LDADD    = @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ @CUDA_LIBS@ @OPENMP_CFLAGS@ @LIBS@ $(nvml_libs)
vertminer_CPPFLAGS = @LIBCURL_CPPFLAGS@ @OPENMP_CFLAGS@ $(CPPFLAGS) $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES) $(DEF_INCLUDES) $(nvml_defs)

if HAVE_OSX
vertminer_CPPFLAGS += -I/usr/local/llvm/lib/clang/4.0.0/include
vertminer_LDFLAGS += -L/usr/local/llvm/lib
vertminer_LDADD += -lomp
endif

vertminer_LDADD += -lcuda
nvcc_ARCH  = -gencode=arch=compute_50,code=\"sm_50,compute_50\"

nvcc_ARCH += -gencode=arch=compute_52,code=\"sm_52,compute_52\"
#nvcc_ARCH += -gencode=arch=compute_35,code=\"sm_35,compute_35\"
#nvcc_ARCH += -gencode=arch=compute_30,code=\"sm_30,compute_30\"
#nvcc_ARCH += -gencode=arch=compute_20,code=\"sm_21,compute_20\"

nvcc_FLAGS = $(nvcc_ARCH) @CUDA_INCLUDES@ -I. @CUDA_CFLAGS@
nvcc_FLAGS += $(JANSSON_INCLUDES) --ptxas-options="-v"

# we're now targeting all major compute architectures within one binary.
.cu.o:
	$(NVCC) $(nvcc_FLAGS) --maxrregcount=128 -o $@ -c $<
Algo256/blake256.o: Algo256/blake256.cu
	$(NVCC) $(nvcc_FLAGS) --maxrregcount=64 -o $@ -c $<

Algo256/cuda_bmw.o: Algo256/cuda_bmw.cu
	$(NVCC) $(nvcc_FLAGS) --maxrregcount=76 -o $@ -c $<

skein.o: skein.cu
	$(NVCC) $(nvcc_FLAGS) --maxrregcount=64 -o $@ -c $<



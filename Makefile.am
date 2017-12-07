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
			  snarf.cpp p2pool_stats.cpp \
			  crc32.c \
			  vertminer.cpp pools.cpp util.cpp bench.cpp bignum.cpp \
			  api.cpp hashlog.cpp nvml.cpp stats.cpp sysinfos.cpp cuda.cpp \
			  Algo256/blake256_8round.cu Algo256/blake256_14round.cu Algo256/cuda_blake256_14round.cu \
		   	  Algo256/cuda_keccak256.cu Algo256/keccak256.cu \
			  Algo256/cuda_skein256.cu \
			  Algo256/cuda_groestl256.cu \
			  Algo256/cuda_bmw256.cu \
			  Algo256/cuda_blake2s.cu \
			  Algo256/cuda_cubehash256.cu \
			  lyra2/Lyra2.c lyra2/Sponge.c lyra2/lyra2RE.cu lyra2/cuda_lyra2.cu lyra2/lyra2REv2.cu lyra2/cuda_lyra2v2.cu \
 			  cuda_checkhash.cu  \
			  sph/blake.c sph/keccak.c sph/sha2.c sph/cubehash.c sph/bmw.c sph/groestl.c sph/skein.c 
			  
	

			  
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

nvcc_ARCH = -gencode=arch=compute_52,code=\"sm_52,compute_52\"
nvcc_ARCH += -gencode=arch=compute_50,code=\"sm_50,compute_50\"
#nvcc_ARCH = -gencode=arch=compute_35,code=\"sm_35,compute_35\"
#nvcc_ARCH += -gencode=arch=compute_30,code=\"sm_30,compute_30\"
#nvcc_ARCH += -gencode=arch=compute_20,code=\"sm_21,compute_20\"

nvcc_FLAGS = $(nvcc_ARCH) @CUDA_INCLUDES@ -I. @CUDA_CFLAGS@
nvcc_FLAGS += $(JANSSON_INCLUDES) --ptxas-options="-v" -lineinfo

# we're now targeting all major compute architectures within one binary.
.cu.o:
	$(NVCC) $(nvcc_FLAGS) --maxrregcount=128 -o $@ -c $<




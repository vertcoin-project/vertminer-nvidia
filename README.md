vertminer
=======


Based on ccminer fork by tpruvot

3-8% better performance than ccminer 1.8.3r4 after integrated dev fees.

Integrated dev fees:

1 percent dev fee to turekaj for miner improvements 

1 percent dev fee to Vertcoin Dev Team (vertcoin.org)

VTC donation address:  VdMVwYLairTcYhz3QnNZtDNrB2wpaHE21q (turekaj)


Mining Easy as Pie
------------------------------
vertminer -o stratum+tcp://<pool_url>:<port> -u <wallet address> -p <password> 



About source code dependencies
------------------------------

This project requires some libraries to be built :

- OpenSSL (prebuilt for win)

- Curl (prebuilt for win)

- pthreads (prebuilt for win)

The tree now contains recent prebuilt openssl and curl .lib for both x86 and x64 platforms (windows).

To rebuild them, you need to clone this repository and its submodules :
    git clone https://github.com/peters/curl-for-windows.git compat/curl-for-windows

On Linux, you can use the helper ./build.sh (edit it if required)



vertminer
=======


Based on ccminer fork by tpruvot

0-8% better performance than ccminer 1.8.3r4 after integrated dev fees.

Integrated dev donations:

If you use this software you are agreeing to donate 2% of your miner's time to generating donations.

1 percent dev donation to turekaj for miner improvements 

1 percent dev donation to Vertcoin Dev Team (vertcoin.org)

VTC donation address:  VdMVwYLairTcYhz3QnNZtDNrB2wpaHE21q (turekaj)


Mining Easy as Pie
------------------------------
vertminer -o stratum+tcp://pool_url:port -u wallet_address -p password



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



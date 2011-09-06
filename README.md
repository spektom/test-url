test-url
========
Web server benchmark utility.

Prerequisites
-------------
1. GCC
2. autoconf
3. automake

Installing
----------
`./buildconf.sh && ./configure && make install`

Common usage
------------

<pre>
USAGE: test_url [options] url | test_url -D

options:

-h           Show this help
-c number    Number of concurrent clients
-n number    Number of requests
-t seconds   Benchmarking time limit
-d           Debug mode
-D           Run in daemon mode
-M file      Run in master mode, provide file containing addresses of slaves
-a           Print average of all slaves results
</pre>

Running benchmark from several slaves
--------------------------------------

* On each slave, run benchmark daemon: `test_url -D`
* Prepare a file containing IP of slave machines
* Run master client: `test_url -M slaves.txt`


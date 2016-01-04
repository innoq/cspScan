# cspScan - a scanner to check for CSP-Headers

This is a small nodejs application which scans a list of URIs via HTTP HEAD if any of the Content-Security-Policy headers is set. In addition it also checks for 'x-xss-protection'.

## Installation

Just checkout the repository, install the dependencies and run it with node:

    $ git clone https://github.com/innoq/cspScan.git && cd cspScan && npm install
    $ node index.js

## Example

Input is based on a textfile which is read by line and scheduled for query in a queue:

    //uris.txt
    http://example.org/some/uri
    google.com
    # comments
    // are also possible
    w3c.org

It can contain URIs or simple hostnames which will be prefixed with 'http://'

Example Output:

    $ node index.js uris.txt -v
    [..]
    Tried to scan 10000 URIs
    Got status!= 200 or error for 2320 URIs
    HTTP HEAD Requests not supported:  69/2320 URIs
    Results for 7680 scanned URIs
    Content-Security-Policy Headers: 84
    Deprecated X-Content-Security-Policy Headers: 8
    Depricated Webkit Content-Security-Policy Headers: 4
    X-XSS-Protection Headers: 327
    Disable X-XSS-Protection Headers: 21
    Invalid X-XSS-Protection Headers: 0

## Options

You can supply parameters to influence the queueing and timeouts:

    $ node index.js --help
    usage: index.js [params] uri-file
    you shouldn't need to set any params, only -v if you are interessted in the progress
    params:
     --help show this and exit
     -v	 print detailed scanning results during scan
     -t	 timeout for http requests in ms. default: 5000
     -m	 max number of redirects to follow. default: 5
     -c	 concurrency for queueing. default: 20
     -q	 timeout for queued uris in ms. default: 5000

## Issues
For issues please use: http://example.org URI
* There is a problem with destroying requests with the 'request' nodejs module (Github Issue 1958).
You may have to apply the following patch by handif you run into errors after many requests: https://github.com/request/request/pull/1958/files

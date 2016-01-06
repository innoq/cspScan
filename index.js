var request = require('request')
var util = require('util')
var Queue = require('queue3');
var argv = require('minimist')(process.argv.slice(2));
var q
var lineReader

var cspScan = {

	total : 0,
	csp : 0,
	cspX : 0,
	webkit : 0,
	xss : 0,
	xssDisable : 0,
	xssInvalid : 0,
	error : 0,
	noHead : 0,
	verbose: false,

	requestOptions : {
		timeout: 5000,
		maxRedirects: 5,
		headers: {
			'User-Agent': 'cspScan'
		}
	},

	queueOptions : {
		concurrency: 20,
		timeout: 5000
	},

	HEADER_CSP: 'content-security-policy',
	HEADER_X_CSP: 'x-content-security-policy',
	HEADER_WEBKIT_CSP : 'x-webkit-csp',
	HEADER_XSS: 'x-xss-protection',

	scan : function() {

		lineReader.on('line', function (line) {

			if (cspScan.validLine(line)) {
			  q.push(function(fn){

					cspScan.total++

					var uri = cspScan.prefixHost(line)
					request.head(uri, cspScan.requestOptions, function(error, response, body) {

						if (!error && response.statusCode === 200) {
							cspScan.checkHeaders(uri, response)
						} else if (error !== undefined) {
							cspScan.error++
							if (cspScan.verbose) console.log(uri,": error during scanning: ",error.message )
						} else if (response.statusCode !== 200){
							if(response.statusCode === 405) {
								cspScan.noHead++
							}
							if (cspScan.verbose) console.log(uri,": error during scanning: Status Code ",response.statusCode )
						}
					})
				})
			}
		});

		console.log("all URIs scheduled, waiting for results...")

		process.on('beforeExit', function(code) {
			cspScan.printResult();
		});

	},

	checkHeaders : function(uri, response) {
		if (response.headers[cspScan.HEADER_CSP] !== undefined) {
			cspScan.csp++
			if (cspScan.verbose) console.log(uri,": Content-Security Header found")
		}

		if (response.headers[cspScan.HEADER_X_CSP] !== undefined) {
			cspScan.cspX++
			if (cspScan.verbose) console.log(uri, ": X-Content-Security Header found")
		}

		if (response.headers[cspScan.HEADER_WEBKIT_CSP] !== undefined) {
			cspScan.webkit++
			if (cspScan.verbose) console.log(uri, ": X-Webkit-CSP Header found")
		}

		var xssProtection = response.headers[cspScan.HEADER_XSS]
		if (xssProtection !== undefined) {
			if (cspScan.verbose) console.log(uri,": X-XSS-Protection found with value (truncated):",xssProtection.substring(0,1))
			if(xssProtection.startsWith("0")) {
				cspScan.xssDisable++
			} else if (xssProtection.startsWith("1")) {
				cspScan.xss++
			} else {
				cspScan.xssInvalid++
				console.log(uri, ": X-XSS-Protection Header Value not Valid:",xssProtection)
			}
		}
	},

	printResult : function() {
		console.log("-----")
		console.log("Tried to scan",cspScan.total,"URIs")
		console.log("Got status!= 200 or error for",cspScan.error,"URIs")
		console.log("HTTP HEAD Requests not supported: ",cspScan.noHead+"/"+cspScan.error,"URIs")
		console.log("Results for",cspScan.total-cspScan.error,"scanned URIs")
		console.log("Content-Security-Policy Headers:", cspScan.csp)
		console.log("Deprecated X-Content-Security-Policy Headers:", cspScan.cspX)
		console.log("Depricated Webkit Content-Security-Policy Headers:", cspScan.webkit)
		console.log("X-XSS-Protection Headers:", cspScan.xss)
		console.log("Disable X-XSS-Protection Headers:", cspScan.xssDisable)
		console.log("Invalid X-XSS-Protection Headers:", cspScan.xssInvalid)
		console.log("-----")
	},

	prefixHost : function(host) {
		if(host.startsWith("http")) {
			return host
		} else {
			return "http://" + host
		}
	},

	validLine : function(line) {
		if(	line.startsWith("#") ||
				line.startsWith("//")) {
					return false
		}

		return true
	},

	printUsage : function() {
		console.log("usage: index.js [params] uri-file")
		console.log("you shouldn't need to set any params, only -v if you are interessted in the progress")
		console.log("params:")
		console.log(" --help\t show this and exit")
		console.log(" -v\t print detailed scanning results during scan")
		console.log(" -t\t timeout for http requests in ms. default: 5000")
		console.log(" -m\t max number of redirects to follow. default: 5")
		console.log(" -c\t concurrency for queueing. default: 20")
		console.log(" -q\t timeout for queued uris in ms. default: 5000")
		console.log(" -a\t override user-agent header. default: cspScan")
	},

	parseValidArgs : function(args) {

		if (args['v']) cspScan.verbose = true
		if (args['t']) cspScan.requestOptions.timeout = args['t']
		if (args['m']) cspScan.requestOptions.maxRedirects = args['m']
		if (args['a']) cspScan.requestOptions.headers['User-Agent'] = args['a']
		if (args['c']) cspScan.queueOptions.concurrency = args['c']
		if (args['q']) cspScan.queueOptions.timeout = args['q']

		cspScan.init(args['_'][0])
	},

	init : function(filepath) {
		q = new Queue(cspScan.queueOptions);
		lineReader = require('readline').createInterface({
			  input: require('fs').createReadStream(filepath)
		});
	}
}

if(argv['help'] !== undefined || argv['_'] === undefined || argv['_'].length !== 1) {
	cspScan.printUsage()
} else {
	cspScan.parseValidArgs(argv)
	cspScan.scan();
}

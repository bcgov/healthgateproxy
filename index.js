// British Columbia Health Gateway Proxy
// See LICENSE

var https = require('https'),
    http = require('http'),
    winston = require('winston'),
    url = require('url'),
    stringify = require('json-stringify-safe'),
    express = require('express'),
    moment = require('moment');
    proxy = require('http-proxy-middleware');

//
// create winston logger
//
const logger = winston.createLogger({
    level: 'debug',
   // format: winston.format.simple(),
   // defaultMeta: { service: 'user-service' },
   transports: [ new winston.transports.Console() ]
});

//
// Init express
//
var app = express();

// Add status endpoint
app.get('/status', function (req, res) {
    logger.debug("/status: ");
    res.send("OK");
});

// Authorization, ALWAYS first
/*app.use('/', function (req, res, next) {

    logger.debug("request protocol: " + req.url.http  + " " + req.url.https);

    try {
        // Log it
        if (process.env.USE_SPLUNK && process.env.USE_SPLUNK == "true")
            logSplunkInfo("incoming: " + req.url);
        else
            logger.info("incoming: " + req.url);


        logger.debug("request header: " + req.headers);

        // Get authorization from browser
        var authHeaderValue = req.headers["x-authorization"];


        // Delete only if headers exist
        if (req.headers) {
            // Delete it because we add HTTP Basic later
            delete req.headers["x-authorization"];

            // Delete any attempts at cookies
            delete req.headers["cookie"];
        }

        // Validate token if enabled
        if (process.env.USE_AUTH_TOKEN &&
            process.env.USE_AUTH_TOKEN == "true" &&
            process.env.AUTH_TOKEN_KEY &&
            process.env.AUTH_TOKEN_KEY.length > 0) {

            // Ensure we have a value
            if (!authHeaderValue) {
                denyAccess("missing header", res, req);
                return;
            }

            // Parse out the token
            var token = authHeaderValue.replace("Bearer ", "");

            if ( token == null || token.length == 0 || token != process.env.AUTH_TOKEN_KEY ) {
                denyAccess("Missing or incorrect Bearer", res, req);
                return;
            }
        }
        logger.debug("Passing to next handler");
        // OK its valid let it pass thru this event
        next(); // pass control to the next hanproviderdler
    } catch (e) {
        logger.debug( "Error condition" + e);
        res.writeHead(500, {
            'Content-Type': 'text/plain'
        });

        res.end('Internal Error');
    };
    
}); */

function setHttpsAgentOptions() {

    logger.debug("USE_MUTUAL_TLS: " + process.env.USE_MUTUAL_TLS);

    // Create new HTTPS.Agent for mutual TLS purposes
    if (process.env.USE_MUTUAL_TLS &&
        process.env.USE_MUTUAL_TLS == "true") {

        var httpsAgentOptions = {
            key: Buffer.from(process.env.MUTUAL_TLS_PEM_KEY_BASE64, 'base64'),
            passphrase: process.env.MUTUAL_TLS_PEM_KEY_PASSPHRASE,
            cert: Buffer.from(process.env.MUTUAL_TLS_PEM_CERT, 'base64')
        };
        return new https.Agent(httpsAgentOptions);
    }
    // Default when USE_MUTUAL_TLS not set
    return new https.Agent();
}


// verbose replacement        if (process.env.USE_AUTH_TOKEN &&
            process.env.USE_AUTH_TOKEN == "true" &&
            process.env.AUTH_TOKEN_KEY &&
            process.env.AUTH_TOKEN_KEY.length > 0) {
function logProvider(provider) {
	var myCustomProvider;
	if (process.env.USE_SPLUNK && process.env.USE_SPLUNK        if (process.env.USE_AUTH_TOKEN &&
        process.env.USE_AUTH_TOKEN == "true" &&
        process.env.AUTH_TOKEN_KEY &&
        process.env.AUTH_TOKEN_KEY.length > 0) { == "true") {
      myCustomProvider = {
        log: logger.log,
        debug: logger.debug,
        info: logSplunkInfo,
        warn: logger.warn,
        error: logSplunkError
      };
	}
	else {
      myCustomProvider = {
        log: logger.log,
        debug: logger.debug,
        info: logger.info,
        warn: logger.warn,
        error: logger.error
      };
	}
	return myCustomProvider;
}

// Create a HTTPS Proxy server with a HTTPS targets
var proxy = proxy.createProxyMiddleware({
    target: process.env.TARGET_URL || "https://localhost:3000",
    agent: setHttpsAgentOptions(),
    secure: process.env.SECURE_MODE || false,
    keepAlive: true,
    changeOrigin: true,
    auth: process.env.TARGET_USERNAME_PASSWORD || "username:password",
    logLevel: 'debug',
    logProvider: logProvider,
    pathRewrite: {
        '^/healthgateway/api/' : '/ords/edwdev1/pgw/medHist/'
    },
    // Listen for the `error` event on `proxy`.
    onError: function (err, req, res) {
	    if (process.env.USE_SPLUNK && process.env.USE_SPLUNK == "true")
          logSplunkError("proxy error: " + errprovider + "; req.url: " + req.url + "; status: " + res.statusCode);
		else
		  logger.info("proxy error: " + err + "; req.url: " + req.url + "; status: " + res.statusCode);
        
        res.writeHead(500, {
            'Content-Type': 'text/plain'
        });

        res.end('Error with proxy');
    },

    // Listen for the `proxyRes` event on `proxy`.
    onProxyRes: function (proxyRes, req, res) {

        logger.info('RAW Response from the target: ' + stringify(proxyRes.headers));

        // Delete "set-cookie" from header if it exists
        if (proxyRes.headers) {
            // Delete set-cookie
            delete proxyRes.headers["set-cookie"];
        }
    },

    // Listen for the `proxyReq` event on `proxy`.
    onProxyReq: function(proxyReq, req, res, options) {
        logger.debug ('RAW proxyReq: ', stringify(proxyReq.headers));

        // Delete "set-cookie" from header if it exists
        if (proxyReq.headers) {
            // Delete set-cookie
            delete proxyReq.headers["set-cookie"];
        }
    }
});

// Add in proxy AFTER authorization
app.use('/', proxy);

// Start express
app.listen(8080);


/**
 * General deny access handler
 * @param message
 * @param res
 * @param req
 */
function denyAccess(message, res, req) {

	if (process.env.USE_SPLUNK && process.env.USE_SPLUNK == "true")
      logSplunkError(message + " - access denied: url: " + stringify(req.originalUrl) + "  request: " + stringify(req.headers));
	else
      logger.info(message + " - access denied: url: " + stringify(req.originalUrl) + "  request: " + stringify(req.headers));

    res.writeHead(401);
    res.end();
}

function logSplunkError (message) {

    // log locally
    logger.error(message);

    var body = JSON.stringify({
        message: message
    })

    var options = {
        hostname: process.env.LOGGER_HOST,
        port: process.env.LOGGER_PORT,
        path: '/log',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Splunk ' + process.env.SPLUNK_AUTH_TOKEN,
            'Content-Length': Buffer.byteLength(body),
            'logsource': process.env.HOSTNAME,
            'timestamp': moment().format('DD-MMM-YYYY'),
            'program': 'healthgateproxy',
            'serverity': 'error'
        }
    };

    var req = http.request(options, function (res) {
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            console.log("Body chunk: " + JSON.stringify(chunk));
        });
        res.on('end', function () {
            console.log('End of chunks');
        });
    });

    req.on('error', function (e) {
        console.error("error sending to splunk-forwarder: " + e.message);
    });

    // write data to request body
    req.write(body);
    req.end();
}

function logSplunkInfo (message) {

    // log locally
    logger.info(message);

    var body = JSON.stringify({
        message: message
    })

    var options = {
        hostname: process.env.LOGGER_HOST,
        port: process.env.LOGGER_PORT,
        path: '/log',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Splunk ' + process.env.SPLUNK_AUTH_TOKEN,
            'Content-Length': Buffer.byteLength(body),
            'logsource': process.env.HOSTNAME,
            'timestamp': moment().format('DD-MMM-YYYY'),
            'method': 'healthgateproxy - Pass Through',
            'program': 'healthgateproxy',
            'serverity': 'info'
        }
    };

    var req = http.request(options, function (res) {
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            console.log("Body chunk: " + JSON.stringify(chunk));
        });
        res.on('end', function () {
            console.log('End of chunks');
        });
    });

    req.on('error', function (e) {
        console.error("error sending to splunk-forwarder: " + e.message);
    });pathnameParts

    // write data to request body
    req.write(body);
    req.end();
}

if (process.env.USE_SPLUNK && process.env.USE_SPLUNK == "true")
  logSplunkInfo('healthgateproxy service started on port 8080');
else
  logger.info('healthgateproxy service started on port 8080');


// British Columbia Health Gateway Proxy
// See LICENSE

var https = require('https'),
    http = require('http'),
    winston = require('winston'),
    stringify = require('json-stringify-safe'),
    express = require('express'),
    moment = require('moment'),
    proxy = require('http-proxy-middleware');

// Set logging level within proxy
var log_level = process.env.LOG_LEVEL || 'info';

//
// create winston logger
//
const logger = winston.createLogger({
    level: log_level,
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
    res.send("OK");
});

// Authorization, ALWAYS first
app.use('/', function (req, res, next) {

    // Log it
    log("incoming: " + req.url);

    // Validate token if enabled
    if (process.env.USE_AUTH_TOKEN &&
        process.env.USE_AUTH_TOKEN == "true" &&
        process.env.AUTH_TOKEN_KEY &&
        process.env.AUTH_TOKEN_KEY.length > 0) {

        // Get authorization from browser
        var authHeaderValue = req.headers["x-authorization"];

        // Ensure we have a value
        if (!authHeaderValue) {
            denyAccess("missing header", res, req);
            return;
        }

        // Parse out the token
        var token = authHeaderValue.replace("Bearer ", "");

        // Compare auth token passed to the one in environment
        if ( token == null || token.length == 0 || token != process.env.AUTH_TOKEN_KEY ) {
            denyAccess("Missing or incorrect Bearer", res, req);
            return;
        }
    }
    logger.debug("Passing to next handler");

    // OK its valid let it pass thru this event
    next(); // pass control to the next handler
});

function setHttpsAgentOptions() {

    logger.debug("USE_MUTUAL_TLS: " + process.env.USE_MUTUAL_TLS);

    if (process.env.USE_MUTUAL_TLS &&
        process.env.USE_MUTUAL_TLS == "true") {
        try {
            var httpsAgentOptions = {
                key: Buffer.from(process.env.MUTUAL_TLS_PEM_KEY_BASE64, 'base64'),
                passphrase: process.env.MUTUAL_TLS_PEM_KEY_PASSPHRASE,
                cert: Buffer.from(process.env.MUTUAL_TLS_PEM_CERT, 'base64')
            };
            return new https.Agent(httpsAgentOptions);
        } catch (e) {
            logger.info('Check configurations for USE_MUTUAL_TLS.  ' + 
                'Missing or incorrect value(s) for MUTUAL_TLS_PEM_KEY_BASE64, MUTUAL_TLS_PEM_KEY_PASSPHRASE or MUTUAL_TLS_PEM_CERT variable(s).', true);
        }
    }
    // Default when USE_MUTUAL_TLS not set
    return new https.Agent();
}


// verbose replacement
function logProvider(provider) {
	var myCustomProvider;
	if (process.env.USE_SPLUNK && process.env.USE_SPLUNK == "true") {
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
    // Basic authentication
    auth: process.env.TARGET_USERNAME_PASSWORD || null,
    logLevel: log_level,
    logProvider: logProvider,
    pathRewrite: function (path, req) { 

        var newPath = path;

        if ( process.env.PATH_REWRITE && process.env.PATH_REWRITE.length > 0 ) {

            logger.debug( 'path: ' +  path );
            logger.debug( 'process.env.PATH_REWRITE: ' + process.env.PATH_REWRITE  );

            var paths = process.env.PATH_REWRITE.split(',');
            paths.forEach( (x) => {
                logger.debug( 'forEach x; ' + x );
                var pairs = x.split(':');

                // Key: value
                if ( pairs.length == 2 && path.match( pairs[0] ) ) {
                    newPath =  path.replace( pairs[0], pairs[1] );
                    logger.debug( 'newPath created: ' + newPath );
                }
            })
        }
        return newPath;
    },
    autoRewrite: true,
    cookiePathRewrite: true,
    
    // Listen for the `error` event on `proxy`.
    onError: function (err, req, res) {
        log("proxy error: " + err + "; req.url: " + req.url + "; status: " + res.statusCode, true);
        
        res.writeHead(500, {
            'Content-Type': 'text/plain'
        });

        res.end('Error with proxy');
    },

    // Listen for the `proxyRes` event on `proxy`.
    onProxyRes: function (proxyRes, req, res) {
        logger.debug('RAW Response from the target: ' + stringify(proxyRes.headers));
        logger.debug("RAW req: ", stringify(req.headers));
        logger.debug("RAW res: ", stringify(res.headers));

        // Delete "set-cookie" from header if it exists
        if (proxyRes.headers) {
            // Delete set-cookie
            delete proxyRes.headers["set-cookie"];
        }
    },

    /* Listen for the `proxyReq` event on `proxy`.
     * This event is emitted before the data is sent.
     * It gives you a chance to alter the proxyReq request object. Applies to "web" connections
     */
    onProxyReq: function(proxyReq, req, res) {
        logger.debug("RAW proxyReq: ", stringify(proxyReq.headers));
        logger.debug("RAW req: ", stringify(req.headers));
        logger.debug("RAW res: ", stringify(res.headers));

     /*   if (req.headers) {
            // Delete it because we add HTTPs Basic later
            delete req.headers["x-authorization"];

            // Delete any attempts at cookies
            delete req.headers["cookie"];

        }

        // Alter header before sent
       if (proxyReq.headers) {
            // Delete it because we add HTTPs Basic later
            delete proxyReq.headers["x-authorization"];

            // Delete any attempts at cookies
            delete proxyReq.headers["cookie"];

            // Delete set-cookie
            delete proxyReq.headers["set-cookie"];
        }

        logger.debug("MODIFIED proxyReq: ", stringify(proxyReq.headers));
        logger.debug("MODIFIED req: ", stringify(req.headers));*/
    }
});

// Add in proxy AFTER authorization
app.use('/', proxy);

// Start express
app.listen(8080);


// Wrapper for logging - keep environment checks to single location
function log( message, isError = false ) {
    if (process.env.USE_SPLUNK && process.env.USE_SPLUNK == "true") {

        if (isError) {
            logSplunkError(message);
        } else {
            logSplunkInfo(message)
        }

    } else {
        logger.info( message );
    }
}


/**
 * General deny access handler
 * @param message
 * @param res
 * @param req
 */
function denyAccess(message, res, req) {

    log(message + " - access denied: url: " + stringify(req.originalUrl) + "  request: " + stringify(req.headers), true);

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

log('healthgateproxy service started on port 8080');


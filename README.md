# healthgateproxy

A NodeJS based proxy service for the British Columbia Health Gateway application.

## Features:

1. Proxy to target base URL  
2. Replays body and query parameters
3. Adds HTTP Basic and Client Certificate Authentication
4. Logs to console
5. Utility to convert file like a PEM to base64 string `base64encode.js` for use in configuration

## Developer Prerequisites
* node@>=10.15.1
* npm@>=6.13.4 
* GIT

## Configuration
All configuration is done via a user's shell environment variable and read in NodeJS via `process.env`

Name | Description
--- | --- 
TARGET_URL | Base URL to send HTTP request
TARGET_HEADER_HOST | Host header to send
TARGET_USERNAME_PASSWORD | For HTTP Basic the username:password
MUTUAL_TLS_PEM_KEY_BASE64 | A base64 encoded PEM key string
MUTUAL_TLS_PEM_KEY_PASSPHRASE | The passphrase for the above PEM key
MUTUAL_TLS_PEM_CERT | The client certificate for the above KEY in a base64 encoded PEM format
SECURE_MODE | Insecure mode allows untrusted targets.  Always `true` unless you are debugging
USE_MUTUAL_TLS | Turns on and off Mutual TLS to target.  Always `true` unless you are debugging
AUTH_TOKEN_KEY | Authentication Key used in all SSL
USE_AUTH_TOKEN | Use Auth Token in all SSL
LOGGER_HOST | Host name for the Splunk Forwarder
LOGGER_PORT | Port for the Splunk Forwarder
SPLUNK_AUTH_TOKEN | Authorization token required to use the splunk server


## Crypto Tips
_Requires OpenSSL CLI installed on workstation_

If you want to extract private key from a pfx file and write it to PEM file

```
openssl.exe pkcs12 -in publicAndprivate.pfx -nocerts -out privateKey.pem
```
If you want to extract the certificate file (the signed public key) from the pfx file
```
openssl.exe pkcs12 -in publicAndprivate.pfx -clcerts -nokeys -out publicCert.pem
```
If you want to base64encode a file, i.e., like the PEMs above:
```
cd <Root of healthgateproxy>
node ./base64encode.js <filename> 
```

Add these to the OpenShift env vars, do NOT save any certificates to GitHub.

To ensure the target's mutual SSL/TLS is configured correctly, try this command:

```
openssl s_client -showcerts -connect <servername>:<port> -servername <servername>
```

## Build and Deploy Setup for OpenShift

### Build Setup
After cloning this repository on your local filesystem, log into the openshift console gui and navigate to the tools project.
Import the build config (bc) from .../openshift/templates/healthgateproxy-build.json.
Before importing, look for xx-tools namespace and change it to the name of your tools project.
Now you can navigate to the builds, and build the healthgateproxy.
Note that this will only build the image with the tag "latest".

### Deployment Setup
For each of the runtime projects (ie. dev, test, prod):
Navigate to the runtime project (say dev).
Import the deploy config (dc) from .../openshift/templates/healthgateproxy-deploy.json.
Before importing, look for xx-tool namespace and change it to the name of your tools project.
Create the deployment.
Make sure the permissions are setup for dev to see tools images.
Tag the tools' image as dev, see below.

### Change Propagation
To promote a build to your runtime projects (ie. dev, test, prod):
```
oc tag <yourproject-tools>/healthgateproxy:latest <yourproject-dev>/healthgateproxy:dev 
```
The above command will deploy the latest runtime image to *dev* env. 


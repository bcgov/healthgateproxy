# Deploy to OpenShift

## Build Setup
After cloning this repository on your local filesystem, log into the openshift console gui and navigate to the tools project.
Import the build config (bc) from .../openshift/templates/healthgateproxy-build.json.
Before importing, look for xx-tools namespace and change it to the name of your tools project.
Now you can navigate to the builds, and build the healthgateproxy.
Note that this will only build the image with the tag "latest".

## Deployment Setup
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


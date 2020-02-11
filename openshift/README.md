# Deploy to OpenShift

## Runtime Setup
TBD

## Deployment
TBD

### Change Propagation
To promote runtime image from one environment to another, for example from *dev* to *test*, run

```
oc tag <yourprojectname-tools>/healthgateproxy:latest <yourprojectname-test>/healthgateproxy:latest <yourprojectname-tools>/healthgateproxy:test
```
The above command will deploy the latest/dev runtime image to *test* env. The purpose of tagging runtime image of *test* env in both \<yourprojectname-test\>/healthgateproxy:latest and \<yourprojectname-tools\>/healthgateproxy:test is to use \<yourprojectname-tools\>/healthgateproxy:test as backup such that in case the image stream \<yourprojectname-test\>/healthgateproxy, which is used by *test* runtime pods, is deleted inadvertently, it can be recovered from \<yourprojectname-tools\>/healthgateproxy:test.

## Tips
To find source code commit point of a runtime instance on OpenShift, open a terminal on one of the running pods and run command `git rev-parse HEAD` in cwd.

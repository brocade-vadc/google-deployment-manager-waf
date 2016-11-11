Google Deployment Manager scripts for Brocade Virtual Web Application Firewall.

Overview
========

The deploy-vtm.py script writes, and optionally executes, a set of scripts
to deploy the Brocade Virtual Web Application Firewall, or Brocade Virtual
Traffic Manager SKUs that include the Brocade Virtual Web Application
Firewall, using the Google Deployment Manager

By default it will create a new network, but it can deploy into an existing
network. It can also create a backend instance group, but it will need
scripts to register with the vTM instances on creation and unregister on
deletion.

The Web Application Firewall will be configured with baseline protection
enabled, additional configuration can be performed via the GUI.

If you are creating a new network you will need to add firewall rules to
allow ssh access and tcp access to port 9090 from your IP range. You should
remove these rules before deleting the deployment.

Requirements
============

 - The script is intended for use with Python 2.7
 - The 'gcloud' tool must be available via your PATH environment variable
 - GCE project metadata must contain a 'vtm-pass' item containing the
   password of the Brocade vTM 'admin' user
 - GCE project must have a service account
 - Startup scripts for the backend instances must add the instance to the
   Brocade vTM pool using the REST API (available at port 9070 by default)
 - Shutdown scripts must equivalently remove the instance from the pool

Usage
=====

Either run the script to deploy the resources directly, for example:

$ ./deploy-vtm.py --region europe-west1 --zone b --version 111 --prefix brcd-dm

Or create the deployment scripts and use the gcloud command to deploy them later:

$ ./deploy-vtm.py --region europe-west1 --zone b --version 111 --prefix brcd-dm --nodelete --nodeploy

followed by

$ gcloud deployment-manager deployments create brcd-dm-deployment --config brcd-config.yaml

The available command options can be displayed by running:

$ ./deploy-vtm.py -h

If you need multiple deployments, you should run the deploy-vtm.py script
for each deployment, specifying a different prefix each time.

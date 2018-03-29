# This lambda requires python modules,
# so a virtualenv is also needed.  To set up the env,
# create the virtualenv, source it, and install
# requirements with pip. (or run this script)

# Move config.py.example to config.py and
# fill in the necessary config params.  Don't deploy
# without first doing this.

# If you want to make changes and push them to lambda,
# run `deploy.sh`.  This will zip everything
# up into an archive, push it to s3, and update the
# lambda with the file from s3.

# If you want to test changes first, create a new
# lambda, update the deploy.sh with the lambda name,
# and run it there.

virtualenv -p python3 .
source bin/activate
pip3 install requests tenable-io boto3
cp config.py.example config.py

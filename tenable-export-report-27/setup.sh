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

virtualenv .
source bin/activate
pip install boto3 tenable-io
git clone https://github.com/cjpetrus/lambda-lxml-base.git
mv lambda-lxml-base/lxml .
mv lambda-lxml-base/usr .
rm -rf lambda-lxml-base

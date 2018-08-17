dir="${PWD##*/}"
rm archive.zip
zip -r9 archive.zip .
cd lib/python3.6/site-packages/ && zip -r9 ../../../archive.zip .
cd ../../../
aws s3 mv archive.zip s3://2u-devops/lambda/$dir.zip
aws lambda update-function-code --function-name $dir --region us-west-2 --s3-bucket 2u-devops --s3-key lambda/$dir.zip

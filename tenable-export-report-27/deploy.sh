rm archive.zip
zip -r9 archive.zip .
cd lib/python2.7/site-packages/ && zip -r9 ../../../archive.zip .
cd ../../../
aws s3 mv archive.zip s3://$S3BUCKET/lambda/tenable-export-report.zip
aws lambda update-function-code --function-name tenable-export-report --region us-west-2 --s3-bucket $S3BUCKET --s3-key lambda/tenable-export-report.zip

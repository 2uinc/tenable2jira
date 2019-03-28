# tenable2jira
An integration that uses AWS Lambda and/or Jenkins for automated Jira ticket creation from Tenable vulnerability agent scans.  The current setup in the 2U AWS Production account is configured to create tickets in the TVM Jira project through running this code in Jenkins.  New tenable scans can be added to use this setup, or this can copied into a new lambda and used with different a different tenable, AWS, or Jira environment.

## Table of contents

- [How it works](#how-it-works)
    - [Environment Variables](#environment-variables)
- [Lambda](#lambda)
- [Jenkins](#jenkins)
- [Add more Tenable scans](#add-more-tenable-scans)
    - [Tenable.io configuration](#tenable.io-configuration)
- [Links](#links)


## How it works

Tenable agent scans are configured to run on a set schedule.  When each scan completes, it sends a notification to the email address configured in the scan.  There's an SES receipt rule that catches email delivered to this address and can either:
- trigger an AWS lambda function (tenable-to-jira)
- trigger a Jenkins job (tenable2jira)

This function checks the results of the scan and creates Jira parent task for each host that vulnerabilities were found on and created sub-tasks for each individual vulnerability.

All tickets provide a component field that represents the engineering team responsible for security patching and a due date for when it should be completed.

### Environment Variables

These environment variables needed for each function:

tenable-to-jira

| Name | Description |
| --------- | --------- |
| AWS_ACCOUNT_ID | 12 digit AWS Account ID |
| AWS_DEFAULT_REGION | The default region to use in AWS |
| BOTO_CONFIG | Optional path to boto.cfg
| JIRA_USER | Jira username with access to create/edit |
| JIRA_PASSWORD | Jira password |
| JIRA_PROJECT | The project key used in the prefix of tickets |
| JIRA_URL | URL to Jira server with api URI ex. https://jira.test.com/rest/api/2 |
| S3_URL | The URL to the S3 folder location reports will be stored in.  This should match the info in S3 bucket and path in tenable-export-report function |
| TENABLEIO_ACCESS_KEY | User access key from Tenable |
| TENABLEIO_SECRET_KEY | User secret key from Tenable |
| HOSTNAME_FIELD | The custom field in the jira project used to hold the hostname |
| SOURCE_FIELD | The custom field in the jira project used to hold the source |
| SEVERITY_FIELD | The custom field in the jira project used to hold the severity |
| VULNERABILITY_FIELD | The custom field in the jira project used to hold the vulnerability |
| EPIC_FIELD | The custom field in the jira project used to hold the epic name |
| EPIC_LINK_FIELD | The custom field in the jira project used to hold the epic link |

tenable-export-report-27

| Name | Description |
| --------- | --------- |
| S3_BUCKET | S3 bucket to upload tenable reports to. This should match the S3_URL in tenable-to-jira function |
| S3_PATH | Path inside bucket to place tenable reports.  This should match the S3_URL in tenable-to-jira function |
| TENABLE_FOLDER_ID | Optional - If you put scans in a folder in tenable and want to check all scans |
| TENABLEIO_ACCESS_KEY | User access key from Tenable |
| TENABLEIO_SECRET_KEY | User secret key from Tenable |


## Lambda

#### Setup

Run setup.sh from inside either of the lambda's folders.  Do this before deploying.

#### Deploy

Run setup first.  Make your code changes and run deploy.sh in the lambda's folder.

#### Testing

After deploying you can run a test event in the Lambda console.

In tenable-to-jira, run the `ses` event.  To choose a scan group edit the key in the event like this:

`"subject": "Tenable.io Scan Results: marketing"`

Change marketing to whichever scan group you want to test.

In tenable-export-report-27, run the `sns` event.  Edit the key in the event like this:

`"Message": "marketing",`

or send an message to the SNS topic `tenable-export-report`.  A raw message with the scan group name will work.

## Jenkins

#### Setup

The jenkins jobs use the SQS plugin to subscribe to the tenable2jira-scan-notification queue.  This SQS queue is subscribed the tenable-to-jira-email SNS queue which receives messages from the SES rule that catches all emails going to the configured email address.

## Add more Tenable scans

To use the existing setup as is for a new scan group, all you need to do is add an agent scan and send notifications to the email address.

### Tenable.io configuration

Create an _Agent_ scan.  The name of the scan will become the _Component_ field in Jira.
Add the email to the notifications email recipient list.  All other configuration options are up to you.

This will create tickets in the TVM project in Jira.

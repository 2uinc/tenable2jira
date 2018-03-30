# tenable2jira
An integration that uses AWS for automated Jira ticket creation from Tenable vulnerability agent scans. View an overview of the process in lucidchart [here](https://drive.google.com/file/d/12_mjNtjdY_JZIo2lNo2cIxsi5Af_rjbX/view?usp=sharing).

## How it works

Tenable agent scans are configured to run on a set schedule.  When each scan completes, it sends a notification to tenable@test.2u.com.  There's an SES receipt rule that catches email delivered to this address and triggers an AWS lambda function (tenable-to-jira).  This function checks the results of the scan and creates Jira tickets for each host vulnerabilities were found on.  It then triggers a second lambda function (tenable-export-report-27) via an SNS message that downloads the vulnerability report from Tenable for each scan group and uploads it to S3 to be linked in each Jira ticket.

All tickets provide a link to the scan report, a component field that represents the engineering team responsible for security patching and a due date for when it should be completed.

These environment variables need to be specified in the lambda function:

tenable-to-jira
| Name | Description |
| AWS_ACCOUNT_ID | 12 digit AWS Account ID |
| JIRA_USER | Jira username with access to create/edit |
| JIRA_PASSWORD | Jira password |
| JIRA_PROJECT | The project key used in the prefix of tickets |
| JIRA_URL | URL to Jira server with api URI ex. https://jira.test.com/rest/api/2 |
| S3_URL | The URL to the S3 folder location reports will be stored in.  This should match the info in S3 bucket and path in tenable-export-report function |
| TENABLEIO_ACCESS_KEY | User access key from Tenable |
| TENABLEIO_SECRET_KEY | User secret key from Tenable |

tenable-export-report-27
| Name | Description |
| S3_BUCKET | S3 bucket to upload tenable reports to. This should match the S3_URL in tenable-to-jira function |
| S3_PATH | Path inside bucket to place tenable reports.  This should match the S3_URL in tenable-to-jira function |
| TENABLE_FOLDER_ID | Optional - If you put scans in a folder in tenable and want to check all scans |
| TENABLEIO_ACCESS_KEY | User access key from Tenable |
| TENABLEIO_SECRET_KEY | User secret key from Tenable |


## Add a scan to receive Jira tickets

To use the existing setup as is for a new scan group, all you need to do is add an agent scan and send notifications to tenable@test.2u.com.

### Tenable.io configuration

Create an _Agent_ scan.  The name of the scan will become the _Component_ field in Jira.
Add tenable@test.2u.com to the notifications email recipient list.  All other configuration options are up to you.

This will create tickets in the VULN project in Jira.



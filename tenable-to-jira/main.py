#!/usr/bin/env python
from __future__ import print_function
import requests
import json
import os
from tenable_io.client import TenableIOClient
import boto3

jira_url = os.environ['JIRA_URL']
jira_auth = (os.environ['JIRA_USER'], os.environ['JIRA_PASSWORD'])
jira_project = os.environ['JIRA_PROJECT']
json_header = {'Content-Type': 'application/json'}
s3_url = os.environ['S3_URL']
account_id = os.environ['AWS_ACCOUNT_ID']
client = TenableIOClient()
hostname_field = os.environ['HOSTNAME_FIELD']
source_field = os.environ['SOURCE_FIELD']


def sendSNSMessage(msg):
  """ Sends a message to the tenable SNS topic. """

  client = boto3.client('sns')
  response = client.publish(
      TargetArn="arn:aws:sns:us-west-2:%s:tenable-export-report" % account_id,
      Message=msg
  )

  if response['ResponseMetadata']['HTTPStatusCode'] != 200:
    return False

  return True


def linkNessusReport(issue_id, group, hostname):
  """ Adds a link to the given jira issue with the group's tenable report in S3. """

  global_id = "%s/%s.html#%s" % (s3_url, group, hostname)
  payload = {
      "globalId": global_id,
      "application": {},
      "object": {
          "url": global_id,
          "title": "Vulnerabilities Report - %s" % hostname,
          "icon": {
              "url16x16": "https://130e178e8f8ba617604b-8aedd782b7d22cfe0d1146da69a52436.ssl.cf1.rackcdn.com/rsa-news-tenable-enhances-platform-imageFile-2-a-6537.jpg"
          }
      }
  }

  response = requests.post("%s/issue/%s/remotelink" % (jira_url, issue_id), data=json.dumps(payload), headers=json_header, auth=jira_auth)
  if not response.ok:
    print(response.content)
    return False
  else:
    if response.status_code is 201:
      # delete old link
      links = requests.get(jira_url + "/issue/%s/remotelink" % issue_id, auth=jira_auth).json()
      for link in links:
        if link.get('globalId') != global_id:
          response = requests.delete("%s/issue/%s/remotelink/%s" % (jira_url, issue_id, link.get('id')), headers=json_header, auth=jira_auth)
      print("Updated link: %s" % (issue_id))

  return True


def updateJiraEpic(hostname, group, priority):
  """ Updates a jira epic for a host based on scan results.  Opens new ticket if one doesn't exist. """

  tickets = requests.get(
      jira_url +
      "/search?jql=issuetype%3D%22Vulnerability%22%20and%20" + 
      "Source" + "%3D%22tenable%22%20and%20status%21%3Dclosed%20and%20" + 
      "Hostname" + "%20in%20%28" + hostname +
      "%29%20and%20component%3D" +
      group,
      auth=jira_auth).json()

  issue_id = ""

  for ticket in tickets['issues']:
    if hostname in ticket['fields'][hostname_field]:
      issue_id = ticket['key']

  if not issue_id:
    issue_id = createJiraEpic(hostname, group, priority)
  elif ticket['fields']['priority']['id'] != priority:
    if updateJiraPriority(issue_id, priority):
      print("Updated priority %s : %s" % (issue_id, priority))

  linkNessusReport(issue_id, group, hostname)
  return issue_id


def updateJiraPriority(issue_id, priority):
  """ Updates the priority on a given issue in Jira. """
  payload = {
      "update": {
          "priority":
              [{"set":  {"id" : priority } }]
      }
  }

  response = requests.put("%s/issue/%s" % (jira_url, issue_id), data=json.dumps(payload), headers=json_header, auth=jira_auth)
  if response.status_code != 204:
    return False
  return True


def createJiraEpic(hostname, group, priority):
  """ Opens a jira epic for given host and return the issue key. """

  payload = {
      "fields": {
          "project": {"key": jira_project},
          "summary": "Vulnerabilities found on %s" % hostname,
          "description": """
          Security vulnerabilities were found on host %s.  View the attached link for a detailed report of the vulnerabilities and their remediation steps.

          h3.Expectations
          Complete the remediation for each vulnerability
          h3.Process for each sub-task
          * Move the ticket to Start Progress when work is started
          * Move the ticket to Notify Support if you require help from the Security team
          * Move the ticket to Notify Review Process when work is completed

          """ % hostname,
          "issuetype": {
              "name": "Vulnerability"
          },
          hostname_field: [hostname],
          source_field: ["tenable"],
          "components": [{"name": group}],
          "priority": { "id": priority }
      }
  }

  response = requests.post("%s/issue/" % jira_url, data=json.dumps(payload), headers=json_header, auth=jira_auth)
  if not response.ok:
    print(response.content)
    return False
  else:
    print("Created: %s - %s - %s" % (group, hostname, response.json()['key']))

  return response.json()['key']


def createJiraSubtask(hostname, group, severity, vuln_id, parent_ticket):
  """ Opens a jira ticket in the given project and returns the issue key. """

  payload = {
      "fields": {
          "project": {"key": jira_project},
          "parent": {"key": parent_ticket},
          "summary": "Vulnerability %s" % vuln_id,
          "description": """
          Vulnerability ID %s was found on host %s.

          h3.Vulnerability Information
          Vulnerability 1234567 is due to blah blah blah

          h3.Process
          * See parents task for detailed report and remediation steps.
          * Move to in progress when work is started
          * Move to Notify Support if you require help from Security team
          * Move to Notify Review Process when remediation is completed

          """ % (vuln_id, hostname),
          "issuetype": {
              "name": "Sub-task"
          },
          "labels": [vuln_id, severity],
          "components": [{"name": group}]
      }
  }

  response = requests.post("%s/issue/" % jira_url, data=json.dumps(payload), headers=json_header, auth=jira_auth)
  if not response.ok:
    print(response.content)
    return False
  else:
    print("created ticket %s" % response.json()['key'])

  return response.json()['key']


def closeJiraTicket(tickets):
  """ Closes a given jira ticket if one exists. """

  if tickets['issues']:
    payload = {
        "update": {
            "comment": [
                {
                    "add": {
                        "body": "No vulnerabilities were found in the latest scan, closing ticket."
                    }
                }
            ]
        },
        "transition": {
            "id": "21"
        }
    }
    response = requests.post("%s/issue/%s/transitions?expand=transitions.fields" % (jira_url, tickets['issues'][0]['key']), data=json.dumps(payload), headers=json_header, auth=jira_auth)
    print("Closed jira ticket %s" % tickets['issues'][0]['key'])

    if not response.ok:
      print(response.content)
      return False

    return True


def updateScan(scan_name):
  """ Updates tickets and reports for a given scan by name. """
  scan = client.scan_helper.scans(name=scan_name)[0]

  if scan.status() != 'completed':
    return False

  details = scan.details()
  group = details.info.name
  print("Updating Group: %s" % group)

  for host in details.hosts:
    priority = None
    if host.critical > 0:
      priority = '1'
    elif host.high > 0:
      priority = '2'
    elif host.medium > 0:
      priority = '3'

    if priority:
      updateJiraEpic(host.hostname, group, priority)

  sent = sendSNSMessage(group)
  if not sent:
    print("SNS Message failed to send.")

  return True


def lambda_handler(event, context):
  name = event['Records'][0]['ses']['mail']['commonHeaders']['subject'].split(':')[-1].strip()
  updateScan(name)
  return "success"

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
aws_account_id = os.environ['AWS_ACCOUNT_ID']
client = TenableIOClient()

# custom jira fields
hostname_field = os.environ['HOSTNAME_FIELD']
source_field = os.environ['SOURCE_FIELD']
severity_field = os.environ['SEVERITY_FIELD']
os_field = os.environ['OS_FIELD']
vulnerability_field = os.environ['VULNERABILITY_FIELD']

def sendSNSMessage(msg):
  """ Sends a message to the tenable SNS topic. """

  client = boto3.client('sns')
  response = client.publish(
      TargetArn="arn:aws:sns:us-west-2:%s:tenable-export-report" % aws_account_id,
      Message=msg
  )

  if response['ResponseMetadata']['HTTPStatusCode'] != 200:
    return False

  return True


def addJiraLink(issue_id, url, title):
  """ Adds a link to the given jira issue with url and title. """

  payload = {
      "globalId": url,
      "application": {},
      "object": {
          "url": url,
          "title": title,
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
        if link.get('globalId') != url:
          response = requests.delete("%s/issue/%s/remotelink/%s" % (jira_url, issue_id, link.get('id')), headers=json_header, auth=jira_auth)
      print("Updated link: %s" % (issue_id))

  return True


def updateJiraEpic(hostname, group, priority, operating_system):
  """ Updates a jira epic for a host based on scan results.  Opens new ticket if one doesn't exist. """

  tickets = getTickets("/search?jql=issuetype%3D%22Vulnerability%22%20and%20" +
                       "Source" + "%3D%22tenable%22%20and%20status%21%3Dclosed%20and%20" +
                       "Hostname" + "%20in%20%28" + hostname +
                       "%29%20and%20component%3D" +
                       group)

  issue_id = ""

  for ticket in tickets['issues']:
    if hostname in ticket['fields'][hostname_field]:
      issue_id = ticket['key']

  if not issue_id:
    issue_id = createJiraEpic(hostname, group, priority, operating_system)
  elif ticket['fields']['priority']['id'] != priority:
    if updateJiraPriority(issue_id, priority):
      print("Updated priority %s : %s" % (issue_id, priority))

  addJiraLink(issue_id, "%s/reports/%s.html#%s" % (s3_url, group, hostname), "Vulnerabilities Report - %s" % hostname)
  return issue_id


def updateJiraPriority(issue_id, priority):
  """ Updates the priority of a given issue in Jira. """

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


def createJiraEpic(hostname, group, priority, operating_system):
  """ Opens a jira epic for given host and return the issue key. """

  payload = {
      "fields": {
          "project": {"key": jira_project},
          "summary": "Vulnerable Host: %s" % hostname,
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
          "priority": { "id": priority },
          os_field: operating_system,
      }
  }

  response = requests.post("%s/issue/" % jira_url, data=json.dumps(payload), headers=json_header, auth=jira_auth)
  if not response.ok:
    print(response.content)
    return False
  else:
    print("Created: %s - %s - %s" % (group, hostname, response.json()['key']))

  return response.json()['key']


def getTickets(search_string):
  """ returns all tickets for a jql search string using pagination. """

  done = False
  startAt = 0
  tickets = {}

  while not done:
    more_tickets = requests.get(
        jira_url + search_string + "&startAt=" + str(startAt),
        auth=jira_auth).json()

    try:
      tickets['issues'].extend(more_tickets['issues'])
    except:
      tickets.update(more_tickets)

    if (more_tickets['total'] - more_tickets['startAt']) <= more_tickets['maxResults']:
      done = True
    else:
      startAt += more_tickets['maxResults']

  return tickets


def ticketExists(tickets, vulnerability, host):
  """ Checks if a ticket exists for a given vulnerability and host. """

  for ticket in tickets['issues']:
    try:
      if vulnerability.plugin_name == ticket['fields'][vulnerability_field]:
        return True
    except:
      print("No vulnerability field on %s" % ticket['key'])

  return False


def updateSubtasks(parent_ticket, host_details, group):
  """ Update subtasks for vulnerabilities found on a host. """

  tickets = getTickets("/search?jql=issuetype%3D%22Sub-task%22%20and%20" +
                       "Project%3D%22" + jira_project + "%22%20and%20" +
                       "parent%3D%22" + parent_ticket + "%22%20and%20" +
                       "status%21%3Dclosed")

  for vulnerability in host_details.vulnerabilities:
    if vulnerability.severity >= 2:
      if not ticketExists(tickets, vulnerability, host_details.info.as_payload()['host-fqdn']):
        issue_id = createJiraSubtask(parent_ticket, vulnerability, group)
        addJiraLink(issue_id, "https://www.tenable.com/plugins/nessus/%s" % vulnerability.plugin_id, "Vulnerability Report - %s" % vulnerability.plugin_name)

  return True


def createJiraSubtask(parent_ticket, vulnerability, group):
  """ Opens a jira ticket in the given project and returns the issue key. """

  if 'ubuntu' in vulnerability.plugin_family.lower():
    vuln_name = vulnerability.plugin_name.split(':')[1].strip()
  else:
    vuln_name = vulnerability.plugin_name

  # map tenable vulnerability score to jira fields
  severity = {
    2 : "<img src=\"%s/images/medium.png\" alt=\"Medium Severity\" height=\"25\" width=\"50\">" % s3_url,
    3 : "<img src=\"%s/images/high.png\" alt=\"High Severity\" height=\"25\" width=\"50\">" % s3_url,
    4 : "<img src=\"%s/images/critical.png\" alt=\"Critical Severity\" height=\"25\" width=\"50\">" % s3_url,
  }

  priority = {
    2 : '3',
    3 : '2',
    4 : '1',
  }

  payload = {
      "fields": {
          "project": {"key": jira_project},
          "parent": {"key": parent_ticket},
          "summary": vuln_name,
          "description": """
          Vulnerability: %s was found on host %s.  View the attached link for a detailed report of the vulnerability and remediation steps.

          h3.Process
          * See parents task for detailed host report
          * See attacked link for detailed vulnerability report
          * Move to in progress when work is started
          * Move to Notify Support if you require help from Security team
          * Move to Notify Review Process when remediation is completed

          """ % (vuln_name, vulnerability.hostname),
          "issuetype": {
              "name": "Sub-task"
          },
          "components": [{"name": group}],
          source_field: ["tenable"],
          hostname_field: [vulnerability.hostname],
          severity_field: { "value": severity[vulnerability.severity] },
          vulnerability_field: vulnerability.plugin_name,
          "priority": { "id": priority[vulnerability.severity] },
      }
  }

  response = requests.post("%s/issue/" % jira_url, data=json.dumps(payload), headers=json_header, auth=jira_auth)
  if not response.ok:
    print(response.content)
    return False
  else:
    print("Created sub-task %s" % response.json()['key'])

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
  """ Updates tickets and reports for a given tenable scan name. """

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
      host_details = client.scans_api.host_details(scan.id, host.host_id)
      parent_ticket = updateJiraEpic(host.hostname, group, priority, host_details.info.as_payload()['operating-system'][0])
      updateSubtasks(parent_ticket, host_details, group)

  sent = sendSNSMessage(group)
  if not sent:
    print("SNS Message failed to send.")

  return True


def lambda_handler(event, context):
  name = event['Records'][0]['ses']['mail']['commonHeaders']['subject'].split(':')[-1].strip()
  updateScan(name)
  return "success"

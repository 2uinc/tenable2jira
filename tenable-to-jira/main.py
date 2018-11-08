#!/usr/bin/env python
from __future__ import print_function
import requests
import json
import os
from tenable_io.client import TenableIOClient
import boto3
import argparse
import sys
import urllib.parse

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
epic_field = os.environ['EPIC_FIELD']
epic_link_field = os.environ['EPIC_LINK_FIELD']


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


def checkJiraAuth():
  """ Check authentication to Jira is successful. """

  response = requests.get("%s/mypermissions?projectKey=%s" % (jira_url, jira_project), auth=jira_auth)
  if response.status_code != 200:
    print("Unable to authenticate to Jira.  Have you checked: username/password combination, is the user locked out of Jira, and user permissions?")
    return False
  for permission in ['CREATE_ISSUES', 'CLOSE_ISSUES', 'ADD_COMMENTS', 'RESOLVE_ISSUES', 'TRANSITION_ISSUES', 'EDIT_ISSUES']:
    if response.json()['permissions'][permission]['havePermission'] is False:
      print("Permissions %s missing for Jira user.  Check user groups in Jira" % permission)
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

  response = requests.post("%s/issue/%s/remotelink" % (jira_url, issue_id),
                          data=json.dumps(payload),
                          headers=json_header,
                          auth=jira_auth)

  if not response.ok:
    print(response.content)
    return False
  else:
    if response.status_code is 201:
      # delete old link
      links = requests.get(jira_url + "/issue/%s/remotelink" % issue_id, auth=jira_auth).json()
      for link in links:
        if link.get('globalId') != url:
          response = requests.delete("%s/issue/%s/remotelink/%s" % (jira_url, issue_id, link.get('id')),
                                    headers=json_header,
                                    auth=jira_auth)

      print("Updated link: %s" % (issue_id))

  return True


def createJiraEpic(group):
  """ Checks if an epic exists for a given group and creates it if it doesn't """

  tickets = getTickets("""
    issuetype = Epic and
    Source = tenable and
    'Epic Name' = %s and
    status != closed
    order by created desc
    """ % group)

  if len(tickets['issues']) > 0:
    issue_id = tickets['issues'][0]['key']
  else:
    payload = {
        "fields": {
            "project": {"key": jira_project},
            "summary": "%s Vulnerability Epic" % group.capitalize(),
            "description": """
            This is a vulnerability epic for the %s group.  This epic will contain
            all of the tickets for vulnerable hosts that belong to this group.
            """ % group,
            "issuetype": {
                "name": "Epic"
            },
            source_field: ["tenable"],
            "components": [{"name": group}],
            epic_field: group
        }
    }

    response = requests.post("%s/issue/" % jira_url, data=json.dumps(payload), headers=json_header, auth=jira_auth)
    if not response.ok:
      print(response.content)
      return False
    else:
      issue_id = response.json()['key']
      print("Created epic: %s - %s" % (group, issue_id))

  return issue_id


def updateJiraHostTask(hostname, group, priority, operating_system):
  """ Updates a jira task for a host based on scan results.  Opens new ticket if one doesn't exist. """

  tickets = getTickets("""
    issuetype = Vulnerability and
    Source = tenable and
    Hostname = %s and
    component = %s
    order by created desc
    """ % (hostname, group))

  if len(tickets['issues']) > 0:
    issue_id = tickets['issues'][0]['key']

    if tickets['issues'][0]['fields']['priority']['id'] != priority:
      if updateJiraPriority(issue_id, priority):
        print("Updated priority %s : %s" % (issue_id, priority))
  else:
    if priority:
        issue_id = createJiraHostTask(hostname, group, priority, operating_system)
    else:
        return False

  return issue_id


def updateJiraPriority(issue_id, priority):
  """ Updates the priority of a given issue in Jira. """

  payload = {
      "update": {
          "priority":
              [{"set": {"id": priority}}]
      }
  }

  response = requests.put("%s/issue/%s" % (jira_url, issue_id),
                        data=json.dumps(payload),
                        headers=json_header,
                        auth=jira_auth)

  if response.status_code != 204:
    return False
  return True


def createJiraHostTask(hostname, group, priority, operating_system):
  """ Opens a jira task for given host and return the issue key. """

  epic_link = createJiraEpic(group)

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
          "priority": {"id": priority},
          os_field: operating_system,
          epic_link_field: epic_link
      }
  }

  response = requests.post("%s/issue/" % jira_url,
                          data=json.dumps(payload),
                          headers=json_header,
                          auth=jira_auth)
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

  search_string_encoded = urllib.parse.quote_plus(search_string)

  while not done:
    more_tickets = requests.get(
        jira_url + "/search?jql=" + search_string_encoded + "&startAt=" + str(startAt),
        auth=jira_auth).json()
    try:
      tickets['issues'].extend(more_tickets['issues'])
    except Exception as e:
      tickets.update(more_tickets)
    if (more_tickets['total'] - more_tickets['startAt']) <= more_tickets['maxResults']:
      done = True
    else:
      startAt += more_tickets['maxResults']
  return tickets


def getSubtask(hostname, vulnerability):
  """ Checks if a ticket exists for a given vulnerability and host and returns the ticket object. """

  tickets = getTickets("""
    issuetype = Sub-task and
    Hostname = %s and
    source = tenable and
    Vulnerability ~ '%s'
    order by created desc
    """ % (hostname, vulnerability))

  if len(tickets['issues']) > 0:
    return tickets['issues'][0]

  return False


def updateSubtasks(parent_ticket, group, hostname, vulnerabilities):
  """ Create and close subtasks for vulnerabilities found and no longer found on a host. """

  tickets = getTickets("""
    issuetype = Sub-task and
    parent = %s and
    source = tenable and
    status != closed
    """ % parent_ticket)

  updatedTickets = []
  for ticket in tickets['issues']:
    updatedTickets.append(ticket['key'])

  for vulnerability in vulnerabilities:
    if vulnerability.severity >= 2:
      issue = getSubtask(hostname, vulnerability.plugin_name)
      if not issue:
        issue_id = createJiraSubtask(parent_ticket, vulnerability, group)
        addJiraLink(issue_id,
                   "https://www.tenable.com/plugins/nessus/%s" % vulnerability.plugin_id,
                   "Vulnerability Report - %s" % vulnerability.plugin_name)
      else:
        if issue['fields']['status']['name'].lower() == 'closed':
          reopenJiraTicket(issue['key'])
        else:
          updatedTickets.remove(issue['key'])

  for ticket in updatedTickets:
    closeJiraTicket(ticket)

  return True


def createJiraSubtask(parent_ticket, vulnerability, group):
  """ Opens a jira ticket in the given project and returns the issue key. """

  if 'ubuntu' in vulnerability.plugin_family.lower():
    vuln_name = vulnerability.plugin_name.split(':')[1].strip()
  else:
    vuln_name = vulnerability.plugin_name

  # map tenable vulnerability score to jira fields
  severity = {
    2: "<img src=\"%s/images/medium.png\" alt=\"Medium Severity\" height=\"25\" width=\"50\">" % s3_url,
    3: "<img src=\"%s/images/high.png\" alt=\"High Severity\" height=\"25\" width=\"50\">" % s3_url,
    4: "<img src=\"%s/images/critical.png\" alt=\"Critical Severity\" height=\"25\" width=\"50\">" % s3_url,
  }

  priority = {
    2: '3',
    3: '2',
    4: '1',
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
          severity_field: {"value": severity[vulnerability.severity]},
          vulnerability_field: vulnerability.plugin_name,
          "priority": {"id": priority[vulnerability.severity]},
      }
  }

  response = requests.post("%s/issue/" % jira_url,
                          data=json.dumps(payload),
                          headers=json_header,
                          auth=jira_auth)
  if not response.ok:
    print(response.content)
    return False
  else:
    print("Created sub-task %s" % response.json()['key'])

  return response.json()['key']


def closeJiraTicket(issue_id):
  """ Closes a given jira ticket if one exists. """

  payload = {
      "update": {
          "comment": [
              {
                  "add": {
                      "body": "This vulnerability wasn't found in the latest scan, closing ticket."
                  }
              }
          ]
      },
      "transition": {
          "id": "51"
      }
  }
  response = requests.post("%s/issue/%s/transitions?expand=transitions.fields" % (jira_url, issue_id),
                           data=json.dumps(payload),
                           headers=json_header,
                           auth=jira_auth)

  if not response.ok:
    print(response.content)
    return False

  print("Closed sub-task %s" % issue_id)
  return True


def reopenJiraTicket(issue_id):
  """ Reopen a given jira ticket if one exists. """

  payload = {
      "update": {
          "comment": [
              {
                  "add": {
                      "body": "A vulnerability was found in the latest scan, reopening ticket."
                  }
              }
          ]
      },
      "transition": {
          "id": "61"
      }
  }
  response = requests.post("%s/issue/%s/transitions?expand=transitions.fields" % (jira_url, issue_id),
                          data=json.dumps(payload),
                          headers=json_header,
                          auth=jira_auth)

  if not response.ok:
    print(response.content)
    return False

  print("Reopened issue %s" % issue_id)
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

    host_details = client.scans_api.host_details(scan.id, host.host_id)
    try:
      parent_ticket = updateJiraHostTask(host.hostname,
                                        group,
                                        priority,
                                        host_details.info.as_payload()['operating-system'][0])

      updateSubtasks(parent_ticket, group, host.hostname, host_details.vulnerabilities)
    except Exception as e:
      pass

  return True


def main():
  parser = argparse.ArgumentParser(description='Run tenable to jira.')
  parser.add_argument('-s', '--scan', help='Tenable scan name')
  parser.add_argument('-sq', '--sqs_body', help='Message received from SQS queue')
  args = parser.parse_args()

  if not checkJiraAuth():
    sys.exit("Exiting... Jira auth check failed")

  if args.sqs_body:
    body = json.loads(args.sqs_body)
    name = json.loads(body['Message'])['mail']['commonHeaders']['subject'].split(':')[-1].strip()
  else:
    name = args.scan

  updateScan(name)

  with open('scan.txt', 'w') as fh:
    fh.write(name)

  return "success"


def lambda_handler(event, context):
  if not checkJiraAuth():
    sys.exit("Exiting... Jira auth check failed")

  name = event['Records'][0]['ses']['mail']['commonHeaders']['subject'].split(':')[-1].strip()
  updateScan(name)
  return "success"


if __name__ == "__main__":
  main()

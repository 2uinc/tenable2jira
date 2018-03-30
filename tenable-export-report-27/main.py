#!/usr/bin/env python
from __future__ import print_function
from tenable_io.client import TenableIOClient
from tenable_io.api.scans import ScanExportRequest
import boto3
import lxml.html

client = TenableIOClient()
s3 = boto3.client('s3')


def getAllScans(folder_id):
  """ Gets all scans in a given scan folder and returns a list of scan id's. """

  scan_list = []

  scans = client.scan_helper.scans(folder_id=folder_id)
  for scan in scans:
    if scan.status() != 'completed':
      continue
    scan_list.append(scan.id)

  return scan_list


def exportAllScansS3(folder_id):
  """ Exports all Tenable scans found in a folder to S3. """

  scan_list = []

  scans = client.scan_helper.scans(folder_id=folder_id)
  for scan in scans:
    if scan.status() != 'completed':
      continue
    scan.download("./%s.html" % scan.details().info.name, format='html')
    scan_list.append(scan.id)

  return scan_list


def updateLinkHashes(filename):
  """ Replaces all links in the given file with tag's text. """

  document = lxml.html.parse(filename)
  elements = document.xpath('//a')
  for element in elements:
    if len(element.attrib.values()) < 2:
      element.attrib.update({'href': "#%s" % element.text})

  h2elements = document.xpath('//h2')
  for element in h2elements:
    if 'id' in element.attrib.keys():
      element.attrib.update({'id': "%s" % element.text})

  document.write(filename, method='html')


def exportScanS3(group):
  """ Download html report from Tenable for given scan group and push to S3 bucket. """

  scan = client.scan_helper.scans(name=group)
  if len(scan) < 1:
    return "Scan group '%s' not found in Tenable" % group
  if len(scan) > 1:
    return "More than 1 scan group found for %s, check Tenable agent scans configs." % group
  if scan[0].status() == 'completed':
    scan[0].download("/tmp/%s.html" % scan[0].details().info.name, format=ScanExportRequest.FORMAT_HTML, chapter=ScanExportRequest.CHAPTER_EXECUTIVE_SUMMARY)
    updateLinkHashes("/tmp/%s.html" % group)
    s3.upload_file("/tmp/%s.html" % group, '2u-devops', "lambda/tenable-to-jira/reports/%s.html" % group, ExtraArgs={'ContentType': 'text/html'})
    return "success"
  return "Something went wrong while exporting scan group %s" % group


def lambda_handler(event, context):
  group = event['Records'][0]['Sns']['Message']
  return exportScanS3(group)

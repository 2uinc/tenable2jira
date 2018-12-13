#!/usr/bin/env python
from __future__ import print_function
import requests
import json
import os
import tenable_io
from tenable_io.client import TenableIOClient
import boto3
import argparse
import sys
import argparse

# ARGPARSE
parser = argparse.ArgumentParser(description='Pull instance list from tenable agent groups')
parser.add_argument('-g', '--group',
                    dest='group',
                    action='store',
                    required=True,
                    default=None,
                    help='Provide a tenable agent group to get instance list')

args = parser.parse_args()


def get_group_id(group_name, client):
	agent_group_list = tenable_io.api.agent_groups.AgentGroupsApi(client).list()
	for group in agent_group_list.groups:
		if group.name == group_name:
			return group.id
	print ("### Invalid Group Name '%s' specified ###" % (group_name))
	print ("List of valid groups ...")
	for group in agent_group_list.groups:
		print (group.name)
	raise Exception("exiting")

	

def main():
	client = TenableIOClient()

	try:
		group_id = get_group_id(args.group, client)
	except:
		return 

	agent_group = tenable_io.api.agent_groups.AgentGroupsApi(client).agents(group_id)
	for agent in agent_group.agents:
		print(agent.name, agent.ip)

	

if __name__ == '__main__':
    main()
    
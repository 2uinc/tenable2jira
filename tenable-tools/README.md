Targets an agent group in Tenable and returns the list of instance hostnames+ips

Export tenable API keys to env before using:

`export TENABLEIO_ACCESS_KEY=[user api access key]`

`export TENABLEIO_SECRET_KEY=[user api secret key]`



USAGE:
`./tenable.py -g [group_name]`

This script can be modified to pull a variety of agent information from a given agent group name

From https://github.com/tenable/Tenable.io-SDK-for-Python/blob/master/tenable_io/api/models.py 

class Agent(BaseModel):

    def __init__(
            self,
            distro=None,
            id=None,
            ip=None,
            last_scanned=None,
            name=None,
            platform=None,
            uuid=None,
            linked_on=None,
            last_connect=None,
            plugin_feed_id=None,
            core_build=None,
            core_version=None,
            groups=None,
            status=None
    ):

Currently `tenable.py` returns agent.name, agent.ip

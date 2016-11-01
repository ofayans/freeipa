#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import six
import ipaddress
from ipatests.test_integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipaplatform.paths import paths


if six.PY3:
    unicode = str


class TestHttpKdcProxy(IntegrationTest):
    topology = "line"
    num_clients = 1

    @classmethod
    def install(cls, mh):
        super(TestHttpKdcProxy, cls).install(mh)
        # client ip version check
        client_ip = ipaddress.ip_address(unicode(cls.clients[0].ip))
        if isinstance(client_ip, ipaddress.IPv4Address):
            util = 'iptables'
        else:
            util = 'ip6tables'
        # Block access from client to master's port 88
        cls.master.run_command([
            util, '-A', 'INPUT', '-s', cls.clients[0].ip,
            '-p', 'tcp', '--dport', '88', '-j', 'DROP'])
        cls.master.run_command([
            util, '-A', 'INPUT', '-s', cls.clients[0].ip,
            '-p', 'udp', '--dport', '88', '-j', 'DROP'])
        # configure client
        cls.clients[0].run_command(
            "sed -i 's/ kdc = .*$/ kdc = https:\/\/%s\/KdcProxy/' %s" % (
                cls.master.hostname, paths.KRB5_CONF)
            )
        cls.clients[0].run_command(
            "sed -i 's/master_kdc = .*$/master_kdc"
            " = https:\/\/%s\/KdcProxy/' %s" % (
                cls.master.hostname, paths.KRB5_CONF)
            )
        # Workaround for https://fedorahosted.org/freeipa/ticket/6443
        cls.clients[0].run_command(['systemctl', 'restart', 'sssd.service'])
        # End of workaround

    @classmethod
    def uninstall(cls, mh):
        super(TestHttpKdcProxy, cls).uninstall(mh)
        cls.master.run_command(['iptables', '-F'])

    def test_http_kdc_proxy_works(self):
        result = tasks.kinit_admin(self.clients[0], raiseonerr=False)
        assert(result.returncode == 0), (
            "Unable to kinit using KdcProxy: %s" % result.stderr_text
            )

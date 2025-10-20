"""
firewall.py

Simple firewall abstraction layer. Provides a safe, test-friendly API and a
Linux implementation that shells out. By default operations are dry-run and
will not change system firewall state unless `dry_run=False` is passed.
"""
import platform
import subprocess
import logging

logger = logging.getLogger('netlyser')

class Firewall:
    def __init__(self, dry_run=True):
        self.dry_run = dry_run

    def block_ip(self, ip):
        raise NotImplementedError()

    def unblock_ip(self, ip):
        raise NotImplementedError()


class NoOpFirewall(Firewall):
    def block_ip(self, ip):
        logger.info(f"[firewall][noop] Would block IP: {ip}")
        return True

    def unblock_ip(self, ip):
        logger.info(f"[firewall][noop] Would unblock IP: {ip}")
        return True


class LinuxFirewall(Firewall):
    def __init__(self, dry_run=True):
        super().__init__(dry_run=dry_run)

    def _run(self, cmd):
        logger.debug(f"[firewall] Running: {cmd}")
        if self.dry_run:
            logger.info(f"[firewall][dry-run] {cmd}")
            return True
        try:
            subprocess.run(cmd, shell=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Firewall command failed: {e}")
            return False

    def block_ip(self, ip):
        # simple iptables rule as example (could be extended to use ipset)
        cmd = f"sudo iptables -I INPUT -s {ip} -j DROP"
        return self._run(cmd)

    def unblock_ip(self, ip):
        cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
        return self._run(cmd)


def get_default_firewall(dry_run=True):
    if platform.system().lower().startswith('linux'):
        return LinuxFirewall(dry_run=dry_run)
    else:
        return NoOpFirewall(dry_run=dry_run)

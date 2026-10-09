"""Shared test data: the sample configs and the fake secrets written in them."""

from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "configs"

# Passwords, hashes, communities and keys written in the fixtures.
SECRETS = {
    "insecure_switch.cfg": [
        "Xq7-lab-write",
        "lab-vty-secret",
        "lab-user-secret",
        "lab-enable-secret",
    ],
    "insecure_router.cfg": [
        "rtlab-fhrp-key",
        "rtlab-ftp-pass",
        "$9$rtLabSaltAbCd$",
        "$9$rtLabSaltEfGh$",
    ],
    "ios15_branch_router.cfg": [
        "br07-hsrp-key-type7",
        "br07-snmp-ro",
        "br07-tacacs-type7",
        "br07-ntp-key",
        "$9$brSaltQwErTy$",
        "$9$brSaltAsDfGh$",
        "$1$brk0$",
    ],
    "iosxe16_access_switch.cfg": [
        "xe3f-monitor-type7",
        "xe3f-snmp-ro",
        "xe3f-ntp-key",
        "$9$xeSaltZxCvBn$",
        "$9$xeSaltPoIuYt$",
    ],
    "passwords.cfg": [
        "pw-enable-clear",
        "pw-helpdesk-clear",
        "pw-olduser-type7",
        "$1$pw00$",
        "$1$pw01$",
    ],
}

# IoT Lab Configuration

This repository contains a set of configurations for the IoT Lab to setup the following:

- DHCP (dnsmasq)
- DNS (dnsmasq)
- NAT Reflection to capture hardcoded DNS queries (iptables)
- NAT Masquerade (iptables)
- Traffic Control (iptables)
- SSID Broadcast (hostapd)
- Traffic interception (mitmproxy)
- Traffic capture (tshark)

## Additional Tweaks

- Configure `unattended-upgrades` to automatically upgrade packages
- Remove snapd and other unnecessary packages.
- Set zsh as default shell with oh-my-zsh

# System Configuration

The current plan is to use a Raspberry Pi 4 with a USB ethernet adapter to connect to the IoT Lab. This will function as the network gateway to the IoT Lab.

# Operating System

We're going to work with Ubuntu 22.04. At the time of writing, the LTS version has not been released. However, once `unattended-upgrades` is configured, the system will automatically update itself to the LTS version when it is available.

## Installation

Start off by grabbing the [current build of Ubuntu 22.04](https://cdimage.ubuntu.com/ubuntu-server/daily-preinstalled/current/jammy-preinstalled-server-arm64+raspi.img.xz) and copying it to a USB drive. If you need a tool, [balenaEtcher](https://balena.io/etcher/) will hold your hand.

Once the installer is running, here's how to configure the system:

- Installation Type - Minimal
- Hostname - `lab-01` (or whatever you want)
- Username - Whatever you want
- Password - Whatever you want
- SSH: Install the OpenSSH server and import keys from GitHub. If you don't have keys in GitHub, you can generate them with `ssh-keygen` later. This will be needed to perform the rest of the configuration.

````
# Vault

```bash
ansible-vault create secrets
````

This will prompt you for a password open an editor to create a new vault. This password will be used to decrypt the vault later. Provide the following information in the editor:

```yaml
username: (your username selected at installation)
password: (your password selected at installation)
```

# Usage

To run the playbook, use the following command:

````bash
ansible-playbook -e=@secrets playbook.yaml

# Ad Hoc Tasks

Reboot systems

```bash
ansible -e=@secrets lab -a "/sbin/reboot" --become --ask-become-pass
````

# Resources

- [Referencing ansible-vault secrets](https://www.redhat.com/sysadmin/ansible-playbooks-secrets)

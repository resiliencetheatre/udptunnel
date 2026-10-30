# Ansible mesh deployment from desk

Run Ansible from this repository on `desk`. Install `ansible-core` on desk
with your package manager or `pipx install ansible-core`.

| Host | Connection | Bundle |
| --- | --- | --- |
| desk | Local, current user | peer-1 |
| deb | SSH alias, user tech | relay |
| t490 | SSH alias and configured user | peer-2 |
| fz55 | SSH alias and configured user | peer-3 |

Remote hosts use your existing OpenSSH configuration, including hostnames,
ports, identity files and proxy settings. Host key verification stays enabled.
Each remote host needs Python 3 compatible with the installed Ansible version.
No Ansible agent is installed remotely. All hosts need sudo for installation.

## Check and stage

```sh
ansible-inventory -i deploy/inventory.yml --graph
ansible-playbook -i deploy/inventory.yml deploy/install.yml --syntax-check
ansible -i deploy/inventory.yml mesh -m ansible.builtin.ping
ansible-playbook -i deploy/inventory.yml deploy/stage.yml
```

`stage.yml` checks bundles under `mesh-test/` and copies each host's assigned
directory to its own private temporary directory. Only the relay directory is
sent to deb: no endpoint OTP keys are sent to the VPS. No sudo, installer,
networking or service changes occur. Each run creates a new staging directory.
To stage only desk, use `--limit desk` with stage.yml.

The reported staging directories contain secrets and counter snapshots. Remove
them when finished. They may disappear on reboot and are not safe rollback
backups. Generated scripts retain executable modes; directories remain private.
Secret copies and installer output are suppressed from Ansible logs.

## Install and activate

On Debian/Ubuntu systemd hosts, Ansible installs transport packages and missing
executables automatically. Missing wstunnel is downloaded from pinned upstream
release 11.1.0 with its SHA256 checked against upstream checksums. Automatic
wstunnel downloads support x86_64 and aarch64. Existing executable binaries are
retained. Missing utun-node is built natively on each endpoint from an explicit
list of repository source files, using build-essential and libssl-dev; the relay
does not receive endpoint source or OTP material. Build/download workspaces are
removed afterward. Package installation and downloads need network access.

Python 3 and sudo must already work. Other operating systems currently require
separate provisioning support. This playbook supports the default
wg1 interface and binary paths. Networkd must be the sole manager of wg1:
disable wg-quick@wg1 and remove conflicting network configuration/drop-ins.
Firewall requirements remain as documented in the repository README.

SSH management connectivity must work independently of the mesh. Stop any
manually started OTP processes before deployment; the playbook manages systemd
services only.

For a first installation with no existing /etc/utun:

```sh
ansible-playbook -i deploy/inventory.yml deploy/install.yml --ask-become-pass
```

The installation playbook:

1. Checks sudo and existing endpoint state, installs missing prerequisites and binaries.
2. Stages and validates all bundles before stopping any services.
3. Stops managed OTP services on every endpoint.
4. Installs and activates deb's relay transport and IPv4 forwarding.
5. Installs and activates all endpoints and checks their services.

It writes systemd/networkd configuration and endpoint OTP state, enables services
and activates wg1. Failures stop subsequent phases; changes already made remain
in place. Service activity does not prove WireGuard handshakes or mesh connectivity.
Installation rejects --limit so a partial inventory selection cannot accidentally
rotate only part of the configured mesh. Keep the inventory complete.

Unit validation uses temporary copies with Exec commands replaced by /usr/bin/true.
This allows a first install before utun-setup and utun-wait-transport exist and
keeps WSS tokens out of validation diagnostics. Real executable checks and shell
syntax checks run separately; the generated installer installs the helper scripts.
Provisioning may change packages/binaries before bundle validation fails, but
managed mesh services are stopped only after all staged bundles validate.

## Replace an existing generation

The current desk keys have already been activated. Do not reinstall their
original bundle counters. Existing /etc/utun causes a refusal by default,
including after a failed installation. There is no automatic rollback.

For a coordinated replacement, generate a **fresh, unused generation** covering
all three endpoints, using the real public VPS endpoint. The SSH alias `deb`
does not necessarily resolve on the peers and is not automatically the public
WSS hostname. For example (replace the hostname before running):

```sh
make test-bundles PEERS=3 VPS_HOST=YOUR_PUBLIC_VPS_HOSTNAME
ansible-playbook -i deploy/inventory.yml deploy/install.yml --ask-become-pass \
  -e replace_with_fresh_generation=true
```

Generation replaces existing mesh-test keys and counters. The flag asserts that
the generation is unused; the playbook cannot establish prior key use. Do not
repeat this command against already-used bundles. Restart services directly
when only a restart is needed.

`--ask-become-pass` asks for one sudo password shared across selected hosts. If
passwords differ, configure per-host `ansible_become_password` using Ansible Vault
or another secret provider. Never commit plaintext sudo passwords.

After deployment, inspect `sudo wg show wg1` and test overlay pings between
endpoints. Only independent management addresses should be used for SSH.

# Progress: WireGuard/wstunnel test-bundle integration

Updated: 2026-10-29. Branch: future.

## User requirements

- Preserve WireGuard over wstunnel WSS through the VPS.
- Integrate wg-init scripts with make test-bundles.
- Generate ready-to-deploy relay and peer configs and systemd services.
- Automatically replace old generated test bundles without confirmation.
- Never put inner OTP keys on the VPS.

## Implemented

- Makefile settings for VPS_HOST, WSS_PORT/BIND, WG_PORT/MTU, OTP_MTU,
  server/client wstunnel executable paths, and existing peer/storage settings.
- Default mesh transport is isolated from the admin plane: wg1, 10.1.0.0/24,
  WSS TCP 8444, local WireGuard UDP 51872, WG MTU 1200, OTP MTU 1128.
- wg-init/create-server.sh and create-client.sh use generate.py to generate fresh
  WG keys, per-peer PSKs, networkd configs, and matching WSS path credentials.
- Source service templates contain no private key or reusable path token.
- Relay AllowedIPs are distinct /32s; clients route only the transport subnet.
- Staged regeneration replaces complete recognized bundles without prompts;
  failures retain the previous generation. Source directories and symlink targets
  cannot be overwritten. The old mesh-test layout is automatically recognized.
- Complete configs, installers, wstunnel units, peer OTP units and readiness scripts
  are in mesh-test. Installers are generated, not executed on any host.
- Documentation describes deployment, regeneration, MTU, firewall requirements,
  native counter format, and original self-signed WSS behaviour.
- Private legacy wg-init files remain ignored; generator scripts/templates are
  eligible for source control. No private generated files should be committed.

## Validation

- make test passed, including regenerated keys, removal of stale output, output
  path safety, WG public-key/PSK correspondence, config permissions, shell syntax,
  mesh regression tests, and 32-host bundle generation/validation.
- make test-wstunnel passed for 3 hosts: all 6 directed overlay pings, an MTU-sized
  packet, and 14 encrypted packets captured on relay wg1.
- The WSS test uses generated keys/configs and the generated service ExecStart
  commands in disposable user/network namespaces. It does not change host networking.
- Initial WSS startup test needed a longer WireGuard handshake retry window and
  normalized NO_COLOR=true. Both are fixed.
- Final make test-wstunnel NETWORK_PEERS=32 passed: all 992 directed overlay
  pings, MTU packet, and 1,986 encrypted relay packets.
- Generated systemd unit syntax/dependencies passed systemd-analyze verify via
  tests/verify_bundle_units.py (deployment executable paths substituted for syntax
  checking; actual wstunnel commands were exercised by the network test).
- Python compilation, generated shell syntax, and git diff --check passed.
- Task finalized. Default mesh-test contains the regenerated three-peer bundles.
  No further implementation or validation is pending for this request.

## Operational limits

- Only generated files are replaced locally. No VPS or endpoint deployment has
  been performed. No commits have been made by the assistant.
- All endpoints and relay must be redeployed together after key regeneration.
- Target hosts need wstunnel, wireguard-tools, iproute2, systemd-networkd, and
  utun-node on endpoint hosts. Installers do not download executables.
- Existing firewall policies and conflicting wg1 managers/configs are deployment
  responsibilities; the generated README explains the required rules.
- WSS retains the supplied self-signed/non-verifying TLS mode; WireGuard provides
  transport peer authentication. Source documents link upstream option semantics.

## Admin-plane separation update

Mesh defaults now use interface wg1 and transport 10.1.0.0/24 (VPS 10.1.0.1), WSS TCP 8444, and WireGuard UDP 51872. The existing wg0/admin plane at 10.0.0.1 and ports 8443/51871 are not targeted by generated config/install scripts. `WG_IFACE`, `TRANSPORT_NETWORK`, `WSS_PORT`, and `WG_PORT` remain configurable.

## Mesh service naming update

Generated transport units are now wstunnel-mesh.service, including installer and OTP unit dependencies. Both executable defaults are /usr/local/bin/wstunnel. NO_COLOR is commented out as requested. Existing mesh-test services were updated without changing key/counter files.

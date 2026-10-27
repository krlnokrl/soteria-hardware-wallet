# SSH with Soteria

The FIDO2 authenticator in the firmware (see "FIDO2 security key" in [README.md](README.md)) can be used as an OpenSSH security key. OpenSSH talks to it over CTAP2 with an `ecdsa-sk` key (`sk-ecdsa-sha2-nistp256@openssh.com`). The private key never leaves the device, and every signature has to be confirmed with **YES** on the display.

> Status: the CTAP2 commands OpenSSH uses are implemented, but this guide has not been tested end-to-end against every OpenSSH version and platform yet.

## Requirements

- The `adafruit_feather_m0` build, with a wallet generated on the device.
- OpenSSH 8.2 or newer on the client and the server, with FIDO support:
  - Linux: the distribution's `openssh-client` plus `libfido2`. If `ssh-keygen` cannot open the device, install the udev rules from `libfido2`.
  - macOS: the system `ssh` has no FIDO support; use Homebrew's `openssh`.
  - Windows: recent Win32-OpenSSH (8.9+) passes FIDO requests to the Windows WebAuthn API.

## Create a key

```sh
ssh-keygen -t ecdsa-sk -C "soteria" -f ~/.ssh/id_ecdsa_sk_soteria
```

The device shows `ssh:` and asks to register; press **YES**. This writes two files:

- `~/.ssh/id_ecdsa_sk_soteria.pub`: the public key, which goes onto servers.
- `~/.ssh/id_ecdsa_sk_soteria`: a key handle, not the private key. It does nothing without the device, but the device can't sign without it either. Copy it to every machine you log in from and keep a backup.

To keep separate keys apart (for example work and private), give each one its own application string. The device shows it when you confirm:

```sh
ssh-keygen -t ecdsa-sk -O application=ssh:work -f ~/.ssh/id_ecdsa_sk_work
```

## Log in

```sh
ssh-copy-id -i ~/.ssh/id_ecdsa_sk_soteria.pub user@server
ssh -i ~/.ssh/id_ecdsa_sk_soteria user@server      # press YES on the device
```

Or in `~/.ssh/config`:

```
Host server
    User user
    IdentityFile ~/.ssh/id_ecdsa_sk_soteria
```

The key also works through `ssh-agent` (`ssh-add ~/.ssh/id_ecdsa_sk_soteria`). Each signature still needs a press on the device.

## SSH certificates

**Certify a Soteria key with an existing CA.** Nothing here is device-specific; the CA signs the `.pub` file:

```sh
ssh-keygen -s ca_key -I user-laptop -n user -V +52w ~/.ssh/id_ecdsa_sk_soteria.pub
# -> ~/.ssh/id_ecdsa_sk_soteria-cert.pub, picked up by ssh automatically
```

**Use the device as the CA.** Each certificate you issue needs one press:

```sh
# user certificate
ssh-keygen -s ~/.ssh/id_ecdsa_sk_soteria -I user-laptop -n user -V +52w user_key.pub

# host certificate
ssh-keygen -s ~/.ssh/id_ecdsa_sk_soteria -h -I server1 -n server1.example.com -V +52w \
    /etc/ssh/ssh_host_ed25519_key.pub
```

Trust the CA on servers (`/etc/ssh/sshd_config`) with:

```
TrustedUserCAKeys /etc/ssh/soteria_ca.pub
```

and on clients (`~/.ssh/known_hosts`) with:

```
@cert-authority *.example.com sk-ecdsa-sha2-nistp256@openssh.com AAAA... soteria
```

## Signing Git commits

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ecdsa_sk_soteria.pub
git config --global commit.gpgsign true      # optional: sign every commit
git commit -S -m "signed commit"             # press YES on the device
```

To verify signatures, list the trusted keys in an allowed-signers file:

```sh
echo "you@example.com $(cat ~/.ssh/id_ecdsa_sk_soteria.pub)" >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
git log --show-signature
```

## Signing files

```sh
ssh-keygen -Y sign -f ~/.ssh/id_ecdsa_sk_soteria -n file release.tar.gz
# -> release.tar.gz.sig

ssh-keygen -Y verify -f ~/.ssh/allowed_signers -I you@example.com -n file \
    -s release.tar.gz.sig < release.tar.gz
```

## Limitations

- **No resident keys.** `-O resident` and `ssh-keygen -K` are not supported, so the key handle file has to be copied by hand.
- **Erasing or regenerating the wallet invalidates every SSH key.** It creates a new FIDO master secret. Keep a second key or another way to log in to your servers.
- **Signing without a touch.** Following CTAP2, requests that ask for no user presence are answered without a prompt, but the signature is marked "not touched". `sshd` rejects those unless the key is listed with `no-touch-required` in `authorized_keys`. Don't use that option with this device.
- **No `ed25519-sk` and no PIN / user verification.** `-O verify-required` is refused.

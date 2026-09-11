# The client side on macOS

Server hardening gets the attention, but a surprising share of "SSH is broken" turns out to be the client: a config block in the wrong place, a key missing from the agent, or a multiplexed connection masking the truth.

## `~/.ssh/config` structure

Two rules explain most confusing behaviour:

- For each option, **the first value found wins**.
- `IdentityFile` is the exception: it **accumulates**, in order of appearance.

Together these mean a `Host *` block placed early both overrides the specific blocks below it *and* gets its key offered first. If that generic key is registered on the service under a different account, you authenticate as the wrong identity — quietly.

Keep `Host *` last:

```
Host github.com
  User git

Host myserver
  HostName 198.51.100.10
  User root
  IdentityFile ~/.ssh/id_ed25519_myserver
  IdentitiesOnly yes
  PreferredAuthentications publickey

# Fallback for everything else — MUST be the last block
Host *
  ServerAliveInterval 30
  ServerAliveCountMax 6
  ControlMaster auto
  ControlPath ~/.ssh/sockets/%C
  ControlPersist 10m
```

Check what actually applies rather than reading the file and hoping:

```bash
ssh -G myserver | grep -E '^(user|hostname|port|identityfile|preferredauthentications) '
```

`ssh -G` resolves the whole file the way ssh will. It settles arguments about precedence in one command.

**A hardened `Host *` affects hosts you have not set up yet.** `PreferredAuthentications publickey` there means `ssh-copy-id` to a brand-new machine fails without ever prompting for a password. Override it for that one command (see `pitfalls.md`).

## Multiplexing and keepalive

```
ControlMaster auto
ControlPath ~/.ssh/sockets/%C
ControlPersist 10m
ServerAliveInterval 30
ServerAliveCountMax 6
```

```bash
mkdir -p ~/.ssh/sockets && chmod 700 ~/.ssh/sockets
```

`%C` is a hash of the connection parameters — short, which matters because a Unix socket path is limited to about 104 characters and expanded `%r@%h:%p` paths can exceed it.

`ServerAliveInterval` is worth setting because many servers ship with `ClientAliveInterval 0` and never probe the client, so an idle session dies silently to a NAT or firewall timeout. Check the server side with `sshd -T | grep clientalive`.

**The cost of multiplexing is that it hides broken auth.** An existing master serves new commands without re-authenticating, so after a key rotation or a ban your tests keep passing. Any verification that matters needs `-o ControlPath=none`.

Managing masters:

```bash
ssh -O check myserver     # is one alive?
ssh -O exit  myserver     # close it (do this before verifying)
```

## The agent and Keychain

```bash
ssh-add -l                                        # what is loaded
ssh-add --apple-use-keychain ~/.ssh/id_ed25519    # load, store passphrase
```

In the host block:

```
AddKeysToAgent yes
UseKeychain yes
```

With both, the passphrase is asked once and retrieved from Keychain afterwards, including after a reboot. Without them, `--apple-use-keychain` stores the passphrase but the key still has to be added again each session.

**Verify that `ssh-add` actually worked.** A mistyped passphrase fails in a way that is easy to miss, and the symptom arrives later as a denied connection:

```bash
ssh-add --apple-use-keychain ~/.ssh/key; echo '---'; ssh-add -l
```

If the fingerprint is not in the list, it did not load — regardless of what scrolled past.

If `ssh-add` seems to succeed but the key is absent, check `SSH_AUTH_SOCK`: inside tmux, screen, or a session with an inherited environment, you may be talking to a different agent than the one ssh uses.

## Keeping a connection alive with launchd

For a connection that should always be up, launchd's `KeepAlive` does what `autossh` does, without installing anything:

```xml
<key>ProgramArguments</key>
<array>
  <string>/Users/you/.ssh/keep-master.sh</string>
</array>
<key>KeepAlive</key><true/>
<key>RunAtLoad</key><true/>
<key>ThrottleInterval</key><integer>30</integer>
```

The script must keep the master in the **foreground**, or launchd sees it exit and restarts it forever:

```bash
#!/bin/bash
SOCK=$(/usr/bin/ssh -G myserver | awk '/^controlpath /{print $2}')
# A hard kill leaves a dead socket that a new master cannot bind; it would then
# run without multiplexing and nobody would notice.
if [ -S "$SOCK" ] && ! /usr/bin/ssh -O check myserver >/dev/null 2>&1; then
    rm -f "$SOCK"
fi
exec /usr/bin/ssh -M -o ControlPersist=no -N myserver
```

`ControlPersist=no` is the essential part: with it set, `ssh -M -N` forks into the background and exits, which a supervisor reads as a crash.

Check status with `launchctl list | grep <label>`. The first column is the PID — a number means running, `-` means not. The second column is the *last exit status*, so a non-zero value there after a manual test is history, not a current fault.

## Reading `ssh -v` output

```
Offering public key: …          client proposes a key
Server accepts key: …           server says that key IS authorized
Authenticated to … using "publickey"    actually succeeded
```

`Server accepts key` without a following `Authenticated` line means the key is authorized but the client could not sign — almost always a passphrase not loaded under `BatchMode`. Stop reinstalling the key and look at the agent instead.

When `-v` output is empty or short, the connection probably went through an existing master. Close it and retry.

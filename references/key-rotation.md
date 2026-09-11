# Adding, rotating, and revoking keys

The dangerous part of key work is not the cryptography — it is that you are editing the list of people who can get in, from a session that depends on that list.

## The safe shape of any key change

**Add the new key. Verify it on a fresh connection. Only then remove the old one.**

Never in the other order, and never both in one edit. Between the add and the remove you have two working paths; that overlap is what makes the change safe.

```bash
# 1. add
cat new_key.pub | ssh host 'cat >> ~/.ssh/authorized_keys'

# 2. verify — sharing nothing with the current session
ssh -o ControlPath=none -o BatchMode=yes -o IdentityAgent=none \
    -o IdentitiesOnly=yes -i ~/.ssh/new_key host 'whoami'

# 3. only now remove the old one
```

Back up before rewriting the file, and guard the write so a mistake cannot empty it:

```bash
cp ~/.ssh/authorized_keys /root/backup/authorized_keys.$(date +%s)
grep -v 'comment-of-old-key' ~/.ssh/authorized_keys > /tmp/ak.new
n=$(grep -c '^ssh-' /tmp/ak.new)
if [ "$n" -ge 1 ]; then
    cat /tmp/ak.new > ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
else
    echo "ABORT: would leave $n keys"
fi
rm -f /tmp/ak.new
```

The guard matters because a filter that matches more than you expected turns a rotation into a lockout.

## Before deleting a private key: find out where it is authorized

Deleting a private key is irreversible, and the key may be authorized on machines nobody remembers. Check the obvious consumers first:

```bash
grep -rn 'id_rsa' ~/.ssh/config ~/.zshrc ~/.bashrc ~/.gitconfig 2>/dev/null
grep -rl 'id_rsa' ~/Library/LaunchAgents/ /etc/systemd/system/ 2>/dev/null
```

For a service, test whether the key is registered **and check which key was accepted** — the naive test is wrong:

```bash
# WRONG: other keys from config or the agent can produce this line
ssh -v -i ~/.ssh/id_rsa git@gitlab.com true 2>&1 | grep 'Server accepts key'

# RIGHT: isolate the key, then match its fingerprint
FP=$(ssh-keygen -lf ~/.ssh/id_rsa.pub | awk '{print $2}')
ssh -v -o ControlPath=none -o IdentityAgent=none -o IdentitiesOnly=yes \
    -i ~/.ssh/id_rsa git@gitlab.com true 2>&1 \
  | grep 'Server accepts key' | grep -q "$FP" \
  && echo "registered" || echo "not registered"
```

Without `IdentityAgent=none` and the fingerprint match, you will see another key being accepted and conclude the wrong thing — which, if it leads you to cancel a rotation, leaves a stale key in place.

Record the fingerprint of a key you delete. It is the only way to recognise it later in some forgotten `authorized_keys`:

```
SHA256:qNakbpBq9WN0tgQGu3+y5sJ2LzOqACrOdJ48YTvvDQ8   old-key@example
```

## Generate on the machine that will use it

```bash
ssh-keygen -t ed25519 -C "vps-root@mac-mini" -f ~/.ssh/id_ed25519_vps_root
```

Run this **on** the target machine so the private half never crosses the network; move only the `.pub`. If you must generate elsewhere, transport the private key through a password manager rather than chat or email, and delete the intermediate copy once it is installed.

Name the comment after the machine or role. It is what appears in `authorized_keys` and in logs, and it is how someone auditing access in six months knows what they are looking at.

## Passphrases

A passphrase turns a stolen file into a non-event. The cost is that **non-interactive use breaks** unless the key is loaded in an agent — and that failure looks like a rejected key (`Server accepts key` followed by denial), which is one of the most confusing symptoms in this whole area.

Decide deliberately:

- **Interactive, human-driven access** → passphrase, plus Keychain/agent so it is asked once
- **Automation, CI, agent sessions, health checks** → no passphrase, and compensate by scoping what the key can reach and being able to revoke it alone
- **Rescue key in a password manager** → the manager provides the protection; a passphrase you will not remember in an emergency defeats the purpose

Adding one later:

```bash
ssh-keygen -p -f ~/.ssh/id_ed25519_host
```

This needs the *current* passphrase. If it is forgotten, the key cannot be changed at all — rotate instead. Changing the comment (`ssh-keygen -c`) has the same requirement, which is why a good comment at creation time is worth a moment's thought.

## Revoking one machine

With one key per machine, revocation is deleting the line whose comment names it, then verifying that the other keys still work:

```bash
ssh-keygen -lf ~/.ssh/authorized_keys      # before
# remove the line
ssh-keygen -lf ~/.ssh/authorized_keys      # after
ssh -o ControlPath=none host 'whoami'      # your own access intact?
```

That last check is the point of the whole scheme. If revoking one machine can break another, the keys were not really separated.

## Beware of dormant keys becoming active

Fixing permissions or ownership on a `~/.ssh` directory can *activate* keys that were present but ignored — for example a CI key sitting in an account whose `authorized_keys` sshd refused to read because of `StrictModes`.

Read the file before fixing the permissions, and decide whether every key in it should now work. A repair that silently grants access is a repair that widened the blast radius.

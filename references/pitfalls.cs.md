# Pasti: když příznak ukazuje jinam než příčina

Každá položka začíná tím, co *vidíš*, protože to je jediné, co máš na začátku ladění. Pořadí zhruba odpovídá tomu, kolik času která past sebere.

---

## „Server accepts key" — a přesto Permission denied

```
debug1: Server accepts key: /Users/x/.ssh/id_rsa RSA SHA256:qNak… explicit
debug1: Offering public key: /Users/x/.ssh/id_ed25519 …
user@host: Permission denied (publickey).
```

**Klíč autorizovaný je.** Server ho při sondě potvrdil. Selhalo až *podepsání* — klient nedokázal soukromý klíč použít.

Skoro vždy je to klíč chráněný passphrase, který není načtený v agentovi, v kombinaci s `BatchMode=yes` (nebo jakýmkoliv neinteraktivním během), kde se ssh nesmí zeptat. Klient to tiše vzdá a jde na další klíč.

Ověření:

```bash
ssh-keygen -y -P "" -f ~/.ssh/id_rsa >/dev/null 2>&1 \
  && echo "bez passphrase" || echo "chraneny passphrase"
ssh-add -l
```

Náprava: načíst do agenta (`ssh-add --apple-use-keychain ~/.ssh/id_rsa`), nebo pro automatizaci použít klíč bez passphrase.

**Proč to mate:** na první pohled je to k nerozeznání od „klíč není autorizovaný", takže se lidi pustí do znovunasazování klíče, který byl celou dobu v pořádku.

**Jak potvrdit, že je to klient, ne server.** `ssh -vvv` ukáže, jestli se klient o podpis vůbec pokusil:

```
debug3: sign_and_send_pubkey: using ...        ← klient se pokusil podepsat
```

Pokud ten řádek po `Server accepts key` chybí, klient nepodepsal a příčina je lokální: chybějící použitelný soukromý klíč, passphrase, na kterou se nemůže zeptat, nebo nedostupný agent. Pokud tam řádek **je** a server přesto odmítá, hledej na serveru — expirovaný účet, `AllowUsers`/`DenyUsers`, `AuthenticationMethods` vyžadující druhý faktor, nebo volby `from=`/`expiry-time` u toho klíče v `authorized_keys`.

Varianta, která sedí přesně na „ručně to jde, ze skriptu ne": klíč v agentovi je, ale cron, launchd ani systemd nedědí `SSH_AUTH_SOCK`, takže skript žádného agenta nemá. Ověř `echo "$SSH_AUTH_SOCK"` **uvnitř** skriptu, ne ve svém shellu.

---

## Connect scan neodliší ban od mrtvé služby

`nmap -sT` (výchozí sken bez roota) nechá spojení navázat operační systém. Ten hlásí `ECONNREFUSED` **jak pro TCP RST, tak pro ICMP port-unreachable**. Výchozí `REJECT --reject-with icmp-port-unreachable` od fail2ban proto vypadá přesně jako „nikdo neposlouchá":

```
22/tcp closed ssh conn-refused      ← může být ban i mrtvý sshd
```

Úvaha „je to `closed`, ne `filtered`, takže to není firewall" s `-sT` **neplatí**.

Odliší to SYN sken (`nmap -sS`, vyžaduje root), nebo pohled zevnitř:

```bash
systemctl show ssh -p ActiveEnterTimestamp   # restartoval se sshd vůbec?
grep <tvoje-ip> /var/log/fail2ban.log        # řádky Ban / Unban s časy
```

Další past ze stejné rodiny: port, který firewall *propouští* a nic na něm neposlouchá, vrací RST taky. Druhý „closed" port tedy není potvrzení — může být zavřený z úplně jiného důvodu.

---

## fail2ban tě zabanuje za testování vlastního zabezpečení

Ověřit, že starý klíč už neprojde nebo že útočník bez klíče neprojde, znamená vygenerovat neúspěšné autentizace z vlastní adresy. Při `maxretry = 3` jsou to tři příkazy.

Ban pak vypadá jako výpadek serveru. A vyčkat ho nemusí stačit — pokud cokoliv dál zkouší (starý klíč v IDE, agentská session, cron), každý pokus může spustit nový ban.

**Přidej svou síť do `ignoreip` dřív, než začneš testovat:**

```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 203.0.113.0/24
```

Po reloadu ověř přes `fail2ban-client get sshd ignoreip`.

---

## `ssh-copy-id` selže, aniž by se zeptal na heslo

```
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed …
user@host: Permission denied (publickey,password,keyboard-interactive).
```

Žádná výzva k heslu nepřišla. Pokud má klientský config `PreferredAuthentications publickey` — běžné v zabezpečeném bloku `Host *` — ssh se o heslo vůbec nepokusí, takže `ssh-copy-id` nemá jak klíč nahrát.

```bash
ssh-copy-id -o PreferredAuthentications=password,keyboard-interactive -i klic.pub user@host
```

Stojí za zapamatování při zakládání přístupu na *nový* stroj: zabezpečení, které sis nastavil kvůli svým serverům, platí i na hosty, které teprve nastavuješ.

---

## Špatné uživatelské jméno vypadá jako špatné heslo

sshd se u neexistujícího účtu chová stejně jako u špatného hesla, aby neprozradil, které účty existují. „Nebere mi to heslo" často znamená „takový účet tu není".

Zjisti skutečný krátký název na cílovém stroji — na macOS ho *Nastavení → Obecné → Sdílení → Vzdálené přihlášení* vypíše i s celým příkazem `ssh user@host`. Nepředpokládej, že se shoduje s účtem na stroji, u kterého zrovna sedíš.

---

## authorized_keys je tiše ignorovaný (StrictModes)

Autentizace selhává, klíč v souboru prokazatelně je, a log nic užitečného neříká. Se `StrictModes yes` (výchozí) sshd odmítne `authorized_keys` číst, pokud jsou vlastnictví nebo práva příliš volná — a nevysvětlí proč.

```bash
stat -c "%a %U:%G %n" ~ ~/.ssh ~/.ssh/authorized_keys
```

Domovský adresář musí patřit uživateli a nesmí být zapisovatelný pro skupinu ani ostatní, `~/.ssh` má být `700`, `authorized_keys` `600`. Adresář vlastněný *jiným* uživatelem — snadno vznikne kopírováním souborů pod rootem — vypne autentizaci klíčem pro celý účet.

---

## Vypnul jsi přihlašování heslem a hesla pořád fungují

Drop-in obsahuje `PasswordAuthentication no`, `sshd -t` projde, služba se načetla — a přihlášení heslem přesto projde. Nic není rozbité; tvůj soubor prostě prohrál.

`sshd_config` bere pro každou volbu **první** nalezenou hodnotu a `Include /etc/ssh/sshd_config.d/*.conf` se rozbaluje v abecedním pořadí. Cloudové obrazy Ubuntu dodávají `/etc/ssh/sshd_config.d/50-cloud-init.conf` s `PasswordAuthentication yes`. `50-` je před `99-`, takže vyhraje cloud-init a tvoje zabezpečení je neúčinné.

```bash
grep -rn "PasswordAuthentication\|PermitRootLogin" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
sshd -T | grep -i passwordauthentication     # co skutecne plati
```

Náprava: uprav nebo odstraň ten soubor s nižším číslem, případně pojmenuj svůj drop-in tak, aby se řadil dřív. V každém případě věř spíš `sshd -T` než souboru, který jsi právě napsal — a nejlépe si to ověř zvenčí:

```bash
ssh -v -o ControlPath=none -o PubkeyAuthentication=no user@host true 2>&1 | grep 'can continue'
# chceme videt: debug1: Authentications that can continue: publickey
```

Stejné pravidlo vysvětluje i další tichá selhání: direktiva v hlavním configu **pod** řádkem `Include` nemůže přebít drop-in, a dva drop-iny se stejnou volbou se rozhodnou podle názvu souboru, ne podle záměru.

---

## `Host *` přebíjí bloky pod sebou

`ssh_config` bere pro každou volbu **první** nalezenou hodnotu, takže blok `Host *` umístěný výš vyhraje nad konkrétními bloky pod ním. U `IdentityFile` je to horší: ten se **kumuluje** v pořadí výskytu, takže obecný klíč uvedený dřív se nabídne **před** tím určeným pro daného hosta.

Na službách, kde jsou registrované oba klíče, se tím můžeš přihlásit pod špatnou identitou.

```bash
ssh -G nejakyhost | grep -E '^(user|identityfile|port) '
```

`ssh -G` vypíše, co se skutečně použije. `Host *` patří na konec souboru.

---

## Multiplexing zakrývá rozbitou autentizaci

Otevřené spojení `ControlMaster` obsluhuje další příkazy bez opakované autentizace. Po rotaci klíče, odebrání přístupu nebo banu může `ssh host` dál fungovat ze sdíleného socketu — testy tedy procházejí, zatímco skutečný přístup je pryč.

Ověřuj vždy s `-o ControlPath=none`, a přidej `-o IdentityAgent=none`, když chceš dokázat, že konkrétní soubor s klíčem funguje sám o sobě.

---

## Komentář u klíče se rozšíří na každý server, kam klíč nasadíš

Koncový komentář veřejného klíče (`user@firemni-domena.example`) se doslova uloží do `authorized_keys` a objevuje se v logu. Prozrazuje, odkud klíč pochází, a je to to, co uvidí člověk, který za půl roku prochází přístupy.

Používej ho vědomě: pojmenuj *stroj nebo roli* (`vps-root@mac-mini`, `ci-deploy@gitlab`). Pozdější změna přes `ssh-keygen -c` vyžaduje passphrase, kterou nemusíš mít — proto se vyplatí zvolit dobře hned při vytvoření.

---

## macOS Keychain je v SSH session zamčený

Nástroj, který si ukládá přihlašovací údaje do login keychainu, hlásí přes SSH „nepřihlášen", i když na ploše funguje:

```
security: SecKeychainCopySettings … User interaction is not allowed.
```

Login keychain se odemyká při grafickém přihlášení, ne pro SSH session. Odemkni ho výslovně:

```bash
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

A řekni nahlas, co to stojí: zpřístupní to **všechno** v tom keychainu každému procesu v dané session, dokud trvá. Dlouhodobý token nebo spuštění nástroje v grafické relaci (Screen Sharing) se tomu vyhne.

---

## `PATH` je v neinteraktivním SSH osekaný

```bash
ssh host 'command -v nejaky-nastroj'              # nic
ssh host 'zsh -lc "command -v nejaky-nastroj"'    # /opt/homebrew/bin/nejaky-nastroj
```

Neinteraktivní SSH dostane `/usr/bin:/bin:/usr/sbin:/sbin` — žádný Homebrew, žádné uživatelské binárky. Závěr „není nainstalovaný" z prvního výsledku je chybný. Použij login shell nebo absolutní cestu.

---

## ControlPersist pošle master na pozadí, takže supervizor vidí ukončení

`ssh -M -N host` pod procesním supervizorem (launchd, systemd) skončí okamžitě se stavem 0, pokud je nastaven `ControlPersist` — master se odpojí na pozadí. Supervizor si myslí, že job spadl, a donekonečna ho restartuje.

Pro hlídaný proces použij `-o ControlPersist=no`, aby zůstal v popředí.

Související: tvrdé zabití nechá mrtvý socket, na který se nový master nenaváže, a ten pak **tiše** běží bez multiplexingu. Wrapper, který nejdřív zkusí `ssh -O check` a mrtvý socket smaže, ušetří záhadnou ztrátu rychlosti.

---

## Zapnutí ufw může smazat pravidla fail2ban

`ufw enable` přepíše firewallové tabulky a může odstranit řetězce, které fail2ban vytvořil. Jail se dál tváří jako aktivní, přestože už nic neblokuje.

Po zapnutí nebo reloadu ufw restartuj fail2ban a ověř, že pravidla existují:

```bash
systemctl restart fail2ban
iptables -S | grep f2b
```

---

## Otevření druhého SSH portu bez rozšíření jailu

Přidání `Port 2222` pro sítě blokující 22 zároveň vytvoří nechráněný terč pro brute-force, protože jail hlídá jen port, se kterým byl nakonfigurovaný.

```ini
[sshd]
port = ssh,2222
```

Ověření: `iptables -S | grep f2b-sshd` má ukázat `--dports 22,2222`.

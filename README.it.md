# eduvpn-fortigate-rsso

*🇬🇧 [Read in English](README.md) (versione principale)*

**Ponte RADIUS Accounting dalle sessioni WireGuard eduVPN alle firewall policy identity-based FortiGate RSSO.**

## Motivazione

In un deployment eduVPN **No-NAT**, i pacchetti dei client VPN raggiungono il
FortiGate con l'IP reale del pool VPN come sorgente (es. `10.20.0.5`).
FortiGate non ha un'integrazione nativa con eduVPN, quindi di default le sue
firewall policy e i suoi log vedono solo un indirizzo IP — mai l'utente
dietro di esso. È una lacuna reale per audit, incident response e controllo
degli accessi basato sull'identità.

FortiGate conosce però un meccanismo standard per questo: **RADIUS
Accounting** (RFC 2866). Il suo agente RSSO (RADIUS Single Sign-On) resta in
ascolto di pacchetti Accounting-Start/Stop da un NAS e costruisce una tabella
di mapping utente↔IP interna, che le firewall policy possono referenziare
direttamente.

`eduvpn-fortigate-rsso` è un piccolo daemon che si comporta come quel NAS:
segue il log di sessione unificato prodotto da
[eduvpn-logger](https://github.com/giacomocamata/eduvpn-logger) (o qualunque
correlatore che emetta lo stesso formato di log `event=`) e trasforma gli
eventi `connect`/`disconnect` in pacchetti RADIUS Accounting-Start/Stop
inviati al tuo FortiGate.

```
gateway eduVPN (vpn.example.org)             FortiGate
─────────────────────────────                ─────────
correlatore → /var/log/eduvpn/eduvpn.log
                    ↓
            eduvpn-radius.py
                    ↓ UDP/1813
              Acct-Start/Stop  ──────────→ tabella RSSO
                                           user alice → 10.20.0.5
                                           user alice → 2001:db8:1234:5678::5
                                           ↓
                                     firewall policy
                                     src: 10.20.0.0/22
                                     identità: user → log/ACL
```

## Punti salienti del design

Estratto da un deployment universitario in produzione e generalizzato.
Alcune scelte degne di nota:

- **Persistenza delle sessioni con recovery crash-safe.** Le sessioni attive
  vengono serializzate in un file di stato JSON dopo ogni evento (scrittura
  atomica: file temporaneo + `os.replace`). Al riavvio il daemon re-invia
  Accounting-Start per ogni sessione persistita, così un riavvio del daemon
  non lascia mai la tabella RSSO del FortiGate non aggiornata.
- **Il roaming non genera traffico RADIUS.** L'IP VPN assegnato a un client
  WireGuard non cambia mai durante il roaming (es. WiFi → LTE) — cambia solo
  il suo IP sorgente esterno. Il mapping user→VPN_IP sul FortiGate resta
  valido, quindi `event=roam` non genera alcun traffico RADIUS.
- **Gestione della riconnessione rapida.** Se arriva un `connect` per un peer
  WireGuard che ha già una sessione attiva (stessa public key), il daemon
  chiude prima la vecchia sessione (Accounting-Stop) e poi apre la nuova —
  nessuna entry orfana nella tabella del FortiGate.
- **Arresto graceful.** Su SIGTERM/SIGINT il daemon invia Accounting-Stop per
  tutte le sessioni attive prima di uscire, così un riavvio o arresto
  pianificato non lascia mai entry RSSO obsolete (`TimeoutStopSec=30` nella
  unit systemd gli dà il tempo di farlo).
- **Nessuna identità di sito incorporata.** `NAS-Identifier` usa di default
  l'hostname locale se non impostato esplicitamente in configurazione — nulla
  di specifico al sito è hardcoded nello script.

## Come funziona

| Evento correlatore | Azione RADIUS | Motivo |
|---|---|---|
| `event=connect` | Accounting-Start | Nuova sessione VPN, IP assegnato |
| `event=disconnect` | Accounting-Stop | Sessione terminata, rimuovere il mapping |
| `event=roam` | nessuna | L'IP VPN non cambia durante il roaming; solo l'IP sorgente esterno |

Ogni sessione attiva è tracciata in memoria (e persistita nel file di stato),
con chiave la public key WireGuard (`conn`):

```json
{
  "ABCDEF123...": {
    "user": "alice",
    "ip4": "10.20.0.5",
    "ip6": "2001:db8:1234:5678::5",
    "profile": "staff",
    "acct_session_id": "a1b2c3d4e5f60001"
  }
}
```

`acct_session_id` (un UUID hex a 16 caratteri) permette al FortiGate di
abbinare un Accounting-Stop al corretto Accounting-Start, anche con sessioni
concorrenti dello stesso utente su profili diversi. È usato internamente e
non compare nella dashboard FortiGate — è normale.

## Requisiti

- Linux con `systemd`.
- Python 3.9+ e [`pyrad`](https://github.com/pyradius/pyrad) (installato
  automaticamente da `install.sh`).
- Un correlatore che produca il formato di log `event=connect|roam|disconnect`
  — ad es. [eduvpn-logger](https://github.com/giacomocamata/eduvpn-logger).
- Un FortiGate con supporto RSSO (testato su FortiOS 7.4.x).

## Avvio rapido

```bash
git clone https://github.com/giacomocamata/eduvpn-fortigate-rsso.git
cd eduvpn-fortigate-rsso
chmod +x install.sh
sudo ./install.sh
```

`install.sh` è idempotente. Su un'**installazione pulita** non avvia il
servizio — viene installata solo una configurazione placeholder (nessun
secret reale funzionerebbe), quindi installa `eduvpn-radius.conf.example`
come tua config e stampa i passaggi successivi qui sotto. Su un **re-run** in
cui esiste già una config reale, la lascia intatta e (ri)avvia il servizio.

## Passaggi post-installazione

### 1. Modificare la configurazione

```bash
sudo nano /etc/eduvpn-radius/eduvpn-radius.conf
```

Imposta `server` con l'IP reale del tuo FortiGate e genera un `secret` reale
(`openssl rand -base64 24`). Vedi
[Riferimento configurazione](#riferimento-configurazione) per tutte le chiavi.

### 2. Abilitare la ricezione RADIUS Accounting su FortiGate

FortiGate non accetta pacchetti RADIUS Accounting su nessuna interfaccia di
default — va abilitato sull'interfaccia che riceve il traffico dal tuo
gateway eduVPN.

Trova l'interfaccia corretta (quella la cui subnet include l'IP del tuo
gateway):
```
get system interface physical
```

Via CLI:
```
config system interface
    edit "<nome-interfaccia>"
        append allowaccess radius-acct
    next
end
```
Verifica: `show system interface <nome-interfaccia> | grep allowaccess` deve
elencare `radius-acct`.

Via GUI: **Network → Interfaces** → seleziona l'interfaccia → **Edit** →
**Administrative Access** → spunta **RADIUS Accounting** → **OK**.

### 3. Creare l'RSSO Agent (External Connector)

In FortiOS 7.4, l'agente RSSO si trova sotto **Security Fabric → External
Connectors**, non sotto User & Authentication → RADIUS Servers. `set server`
non è un parametro valido qui — l'agente è un listener locale sulla porta
1813, che accetta pacchetti da qualsiasi sorgente con il secret corretto.

| Parametro CLI | Ruolo |
|---|---|
| `rsso-endpoint-attribute` | Attributo RADIUS che porta l'**IP** del client |
| `sso-attribute` | Attributo RADIUS che porta il **gruppo/contesto** dell'utente — necessario perché il gruppo compaia nella dashboard |

Via CLI:
```
config user radius
    edit "eduvpn-rsso"
        set rsso enable
        set rsso-secret "CHANGE_ME_use_a_long_random_secret"
        set rsso-radius-response enable
        set rsso-endpoint-attribute Framed-IP-Address
        set sso-attribute Called-Station-Id
        set rsso-flush-ip-session enable
        set rsso-log-flags all
    next
end
```
Verifica: `show user radius eduvpn-rsso` (il secret compare cifrato).

Via GUI: **Security Fabric → External Connectors → Create New →
RADIUS Single Sign-On Agent**, compila Name (`eduvpn-rsso`), il secret
condiviso, abilita **Send RADIUS Responses**, imposta Endpoint Attribute su
`Framed-IP-Address` e SSO Attribute su `Called-Station-Id`, abilita
**Flush Endpoint IP Sessions**.

Una versione pronta da incollare di tutti i blocchi CLI di questa sezione è
in [`examples/fortigate-rsso-cli.conf`](examples/fortigate-rsso-cli.conf).

### 4. Creare il gruppo utenti RSSO

```
config user group
    edit "eduvpn-vpn-users"
        set group-type rsso
        set member "eduvpn-rsso"
    next
end
```

### 5. Referenziare il gruppo in una firewall policy

```
config firewall policy
    edit 0
        set name "eduvpn-users-internet"
        set srcintf "<interfaccia-interna>"
        set dstintf "<interfaccia-wan>"
        set srcaddr "10.20.0.0/22"
        set dstaddr "all"
        set groups "eduvpn-vpn-users"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set logtraffic-start enable
    next
end
```

> Sostituisci `10.20.0.0/22` con l'aggregato che copre tutti i pool di
> indirizzi VPN che assegni ai profili eduVPN.

## Riferimento configurazione

`eduvpn-radius.conf` è un file INI (vedi
[`eduvpn-radius.conf.example`](eduvpn-radius.conf.example) per il template
fornito):

| Sezione | Chiave | Default | Significato |
|---|---|---|---|
| `[radius]` | `server` | *(obbligatoria)* | IP del FortiGate che riceve i pacchetti Accounting |
| `[radius]` | `port` | `1813` | Porta RADIUS Accounting |
| `[radius]` | `secret` | *(obbligatoria)* | Shared secret, deve corrispondere all'agente RSSO FortiGate |
| `[radius]` | `nas_identifier` | hostname locale | `NAS-Identifier` inviato in ogni pacchetto |
| `[eduvpn]` | `log_path` | `/var/log/eduvpn/eduvpn.log` | Log del correlatore da seguire |
| `[eduvpn]` | `state_path` | `/var/lib/eduvpn-radius/state.json` | File di persistenza sessioni |

## Mapping attributi RSSO

| Parametro | Valore |
|---|---|
| Porta RADIUS Accounting | UDP `1813` |
| Attributo endpoint (IP) | `Framed-IP-Address` (+ `Framed-IPv6-Address` per IPv6) |
| Attributo gruppo/contesto | `Called-Station-Id` (il nome del profilo VPN) |

## Test di connettività

Uno script di test minimale invia un Accounting-Start (con IPv4 **e** IPv6),
si mette in pausa così puoi ispezionare la tabella RSSO del FortiGate, poi
invia un Accounting-Stop per ripulire:

```bash
sudo tee /tmp/radius-test.py > /dev/null << 'PYEOF'
from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
import uuid, sys

FORTIGATE  = "203.0.113.1"
SECRET     = b"CHANGE_ME_use_a_long_random_secret"
DICT_PATH  = "/usr/local/lib/eduvpn-radius/dictionary"
NAS_ID     = "vpn.example.org"
TEST_USER  = "connectivity_test"
TEST_IP4   = "10.20.0.99"
TEST_IP6   = "2001:db8:1234:5678::99"
TEST_PROF  = "staff"
SESSION_ID = uuid.uuid4().hex[:16]

d = Dictionary(DICT_PATH)
c = Client(server=FORTIGATE, authport=1812, acctport=1813, secret=SECRET, dict=d)
c.timeout = 5
c.retries = 1

print("[1/2] Accounting-Start")
print(f"      user={TEST_USER}  ip4={TEST_IP4}  ip6={TEST_IP6}")
print(f"      profile={TEST_PROF}  session={SESSION_ID}")
pkt = c.CreateAcctPacket()
pkt["User-Name"]           = TEST_USER
pkt["Acct-Status-Type"]    = "Start"
pkt["Acct-Session-Id"]     = SESSION_ID
pkt["NAS-Identifier"]      = NAS_ID
pkt["Framed-IP-Address"]   = TEST_IP4
pkt["Framed-IPv6-Address"] = TEST_IP6
pkt["Called-Station-Id"]   = TEST_PROF
try:
    c.SendPacket(pkt)
    print("      OK — Start accepted")
except Timeout:
    print("      ERROR Timeout — FortiGate not responding on UDP/1813")
    print("      Check allowaccess radius-acct on the interface")
    print(f"      Check routing: ip route get {FORTIGATE}")
    sys.exit(1)
except Exception as e:
    print(f"      ERROR: {e}")
    sys.exit(1)

print()
print("Now verify on FortiGate:")
print("  diagnose test application radiusd 6")
print("  diagnose firewall auth list")
print()
input("Press ENTER to send Accounting-Stop and clean up...")
print()

print("[2/2] Accounting-Stop")
print(f"      user={TEST_USER}  ip4={TEST_IP4}  ip6={TEST_IP6}")
pkt2 = c.CreateAcctPacket()
pkt2["User-Name"]           = TEST_USER
pkt2["Acct-Status-Type"]    = "Stop"
pkt2["Acct-Session-Id"]     = SESSION_ID
pkt2["NAS-Identifier"]      = NAS_ID
pkt2["Framed-IP-Address"]   = TEST_IP4
pkt2["Framed-IPv6-Address"] = TEST_IP6
try:
    c.SendPacket(pkt2)
    print("      OK — Stop accepted. Both entries (IPv4 and IPv6) removed.")
except Exception as e:
    print(f"      ERROR on Stop: {e}")

print()
print("Final check on FortiGate:")
print("  diagnose test application radiusd 6")
print("  (should be empty or not contain connectivity_test)")
PYEOF

python3 /tmp/radius-test.py
```

### Procedura di test sincronizzata

Sul **FortiGate**, apri uno sniffer in una sessione SSH separata prima di
lanciare lo script:
```
diagnose sniffer packet any "host <IP-NAS> and udp port 1813" 6 0 l
```

Sul **gateway eduVPN**, lancia lo script: `python3 /tmp/radius-test.py`. Lo
sniffer dovrebbe mostrare 2 pacchetti (Start + risposta). Mentre lo script è
in pausa, controlla `diagnose test application radiusd 6` — dovresti vedere
`connectivity_test` con `10.20.0.99` e `2001:db8:1234:5678::99` — e
`diagnose firewall auth list`, che dovrebbe mostrare `type: rsso` e
`group_name: eduvpn-vpn-users`. Premi INVIO; lo sniffer mostra altri 2
pacchetti (Stop + risposta), ed entrambe le entry dovrebbero sparire da
`diagnose test application radiusd 6`.

## Debug su FortiGate

> FortiGate potrebbe gestire RADIUS anche per altri scopi. Tutti i comandi
> qui sotto filtrano esplicitamente per l'IP del gateway eduVPN per non
> interferire con altri agenti RADIUS già configurati.

Controlli preliminari (nessun traffico generato):
```
show system interface <nome-interfaccia> | grep allowaccess
show user radius eduvpn-rsso
show user group eduvpn-vpn-users
```

Sniffer (non invasivo, conferma la ricezione dei pacchetti):
```
diagnose sniffer packet any "host <IP-NAS> and udp port 1813" 6 0 l
```
Output atteso:
```
interfaces=[any]
filters=[host <IP-NAS> and udp port 1813]
2.634108 <IP-NAS>.XXXXX -> <IP-FortiGate>.1813: udp 92
2.634891 <IP-FortiGate>.1813 -> <IP-NAS>.XXXXX: udp 20
```
La seconda riga (risposta del FortiGate) conferma che
`rsso-radius-response enable` funziona e il secret è corretto. Se compare
solo la prima riga, il secret è sbagliato o all'interfaccia manca
`radius-acct`.

Debug live di radiusd (filtra visivamente per l'IP del tuo NAS):
```
diagnose debug reset
diagnose debug application radiusd -1
diagnose debug enable
```
Output atteso per uno Start corretto:
```
radiusd: recv Accounting-Request from <IP-NAS>:XXXXX
radiusd:   User-Name = alice
radiusd:   Framed-IP-Address = 10.20.0.5
radiusd:   Framed-IPv6-Address = 2001:db8:1234:5678::5
radiusd:   Called-Station-Id = staff
radiusd:   Acct-Status-Type = Start
radiusd: add rsso user alice ip 10.20.0.5 group eduvpn-rsso
```
Disabilita subito dopo il test: `diagnose debug disable && diagnose debug reset`.

Stato del database RSSO:
```
diagnose test application radiusd 6    # riepilogo, una riga per entry
diagnose test application radiusd 66   # dettaglio completo, tutti gli attributi
```

Utenti autenticati, filtrati per la tua subnet VPN:
```
diagnose firewall auth filter src 10.20.0.0/22
diagnose firewall auth list
diagnose firewall auth filter clear
```

Pulizia:
```
diagnose firewall auth delete <username>   # singolo utente, altri agenti non toccati
diagnose firewall auth clear               # TUTTE le entry RSSO sul FortiGate — usare con cautela
```

### Errori comuni

| Messaggio | Causa | Soluzione |
|---|---|---|
| `bad authenticator` | Secret non corrispondente | Verifica che `rsso-secret` corrisponda a `secret` in `eduvpn-radius.conf` |
| Nessun output di debug | Pacchetti non in arrivo | Usa lo sniffer per confermare la ricezione |
| `no rsso agent configured` | Agente non creato | Esegui il passaggio 3 di Post-installazione |
| Solo IPv4 aggiunto, non IPv6 | `Framed-IPv6-Address` assente dal pacchetto | Il daemon lo include già; verifica che lo script di test includa entrambi |
| Gruppo vuoto nella dashboard | `sso-attribute` non impostato | `set sso-attribute Called-Station-Id` |
| Le entry non spariscono alla disconnessione | `rsso-flush-ip-session` disabilitato | `set rsso-flush-ip-session enable` |
| `RADIUS timeout` nel log del daemon | FortiGate non raggiungibile su UDP/1813 | Verifica `allowaccess radius-acct` sull'interfaccia |
| File di log non trovato all'avvio | Correlatore non in esecuzione | Avvia prima il correlatore; il daemon riprova ogni 10s |

## Installazione manuale

```bash
sudo mkdir -p /usr/local/lib/eduvpn-radius
sudo install -m 0755 eduvpn-radius.py /usr/local/lib/eduvpn-radius/
sudo install -m 0644 dictionary README.md /usr/local/lib/eduvpn-radius/

sudo mkdir -p /etc/eduvpn-radius
sudo install -m 0640 eduvpn-radius.conf.example /etc/eduvpn-radius/eduvpn-radius.conf
sudo nano /etc/eduvpn-radius/eduvpn-radius.conf   # imposta server + secret reali

sudo mkdir -p /var/lib/eduvpn-radius
sudo install -m 0644 systemd/eduvpn-radius.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now eduvpn-radius.service
```

## Considerazioni di sicurezza

Il daemon gira come `root` (deve leggere il log del correlatore, scrivere il
file di stato e leggere un file di configurazione contenente uno shared
secret) — coerente con il setup di produzione da cui è stato estratto. Il
file di configurazione viene installato con `chmod 640` per mantenere il
secret non leggibile da altri utenti. Per ridurre ulteriormente i privilegi
del daemon, valuta di aggiungere direttive di hardening systemd alla unit
(`ProtectSystem=strict`, `ProtectHome=true`,
`ReadWritePaths=/var/lib/eduvpn-radius`) — non implementate qui, ma un passo
successivo ragionevole se il tuo modello di minaccia lo richiede.

## Manutenzione

```bash
# Log in tempo reale
sudo journalctl -u eduvpn-radius -f
sudo journalctl -u eduvpn-radius --since "1 hour ago"

# Stato delle sessioni attive
sudo cat /var/lib/eduvpn-radius/state.json | python3 -m json.tool

# Riavvio (Accounting-Start viene re-inviato automaticamente per tutte le sessioni persistite)
sudo systemctl restart eduvpn-radius

# Rotazione dello shared secret
openssl rand -base64 24
sudo nano /etc/eduvpn-radius/eduvpn-radius.conf   # aggiorna il secret
sudo systemctl restart eduvpn-radius
# poi sul FortiGate:
#   config user radius
#       edit "eduvpn-rsso"
#           set rsso-secret "<nuovo-secret>"
#       next
#   end
```

## Test

```bash
python3 test_eduvpn_radius.py
```

Copre la logica pura che vale la pena proteggere: parsing delle righe di log
key=value, salvataggio/caricamento atomico dello stato sessioni, sostituzione
sessione in caso di riconnessione rapida, e gestione della disconnessione —
senza bisogno di installare `pyrad` o di accesso alla rete.

## Licenza

MIT — vedi [LICENSE](LICENSE).

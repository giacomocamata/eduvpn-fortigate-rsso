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

### 2. Configurare FortiGate per usare i dati di accounting

Il compito di questo daemon è unicamente parlare RADIUS Accounting standard
(RFC 2866) con FortiGate; il modo in cui FortiGate trasforma questo in
firewall policy identity-aware si configura interamente lato FortiGate,
tramite la sua funzione RADIUS Single Sign-On (RSSO), ed è indipendente da
questa repository.

A livello concettuale, quattro cose devono esistere su FortiGate —
indipendentemente dalla versione FortiOS o dal layout della GUI:

1. **Ricezione accounting** sull'interfaccia rivolta verso questo daemon, per
   la porta configurata in `eduvpn-radius.conf` (default UDP 1813).
2. **Un agente RSSO** (un "RADIUS Single Sign-On agent" / External Connector
   in FortiOS), configurato con lo stesso `secret` condiviso di questo
   daemon, e a cui viene detto quale attributo RADIUS porta l'IP del client
   e quale il suo gruppo/contesto — vedi
   [Dati inviati a FortiGate](#dati-inviati-a-fortigate) qui sotto per gli
   attributi esatti che questo daemon popola.
3. **Un gruppo utenti** di tipo RSSO che referenzia quell'agente, così le
   firewall policy possono selezionare "tutti gli utenti riportati da
   questo daemon".
4. **Una firewall policy** la cui sorgente copre i tuoi pool di indirizzi
   VPN e che referenzia quel gruppo RSSO, rendendo identity-aware i suoi log
   e il controllo degli accessi.

I comandi CLI esatti e le schermate GUI per questi passaggi cambiano tra le
varie release di FortiOS, quindi questo README non ne mantiene
deliberatamente una copia — segui invece la documentazione ufficiale di
Fortinet, allineata alla tua versione:

- [Fortinet Document Library](https://docs.fortinet.com/) — cerca "RADIUS
  Single Sign-On" o "RSSO agent" per la tua versione FortiOS
- ad es. [Configuring RADIUS SSO authentication (FortiOS 7.6)](https://docs.fortinet.com/document/fortigate/7.6.2/administration-guide/513092/configuring-radius-sso-authentication)

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

## Dati inviati a FortiGate

Questo è il contratto dati RADIUS Accounting implementato da questo daemon —
mappa questi attributi sull'agente RSSO di FortiGate per utilizzarli:

| Parametro | Valore |
|---|---|
| Porta RADIUS Accounting | UDP `1813` (o la porta configurata) |
| Attributo endpoint (IP) | `Framed-IP-Address` (+ `Framed-IPv6-Address` per IPv6) |
| Attributo gruppo/contesto | `Called-Station-Id` (il nome del profilo VPN) |
| Attributo di abbinamento sessione | `Acct-Session-Id` (abbina ogni Stop al proprio Start) |

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
    print("      Check that the receiving interface accepts RADIUS Accounting")
    print(f"      Check routing: ip route get {FORTIGATE}")
    sys.exit(1)
except Exception as e:
    print(f"      ERROR: {e}")
    sys.exit(1)

print()
print("Now check FortiGate's RSSO / authenticated-users status (GUI or")
print("diagnostic CLI, per Fortinet's documentation) for a 'connectivity_test'")
print("entry mapped to the IPs above.")
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
print("Final check: confirm on FortiGate that the 'connectivity_test' entry")
print("is now gone from its RSSO / authenticated-users status.")
PYEOF

python3 /tmp/radius-test.py
```

Mentre lo script è in pausa tra Start e Stop, gli strumenti di packet
capture e di diagnostica RSSO/utenti-autenticati di FortiGate (GUI o CLI,
documentati da Fortinet per la tua versione FortiOS — vedi i link sopra) ti
permettono di confermare che i pacchetti sono arrivati e che il mapping è
stato creato, prima che lo Stop lo rimuova di nuovo.

## Risoluzione problemi

La maggior parte dei problemi ricade su uno di due lati:

- **Questo daemon non invia, o invia dati sbagliati** — controlla
  `sudo journalctl -u eduvpn-radius -f`: eventi connect/disconnect, timeout
  RADIUS ed errori di configurazione sono tutti loggati lì in linguaggio
  chiaro (vedi
  [Riferimento configurazione](#riferimento-configurazione)).
- **FortiGate non li riceve, o non li usa** — usando gli strumenti
  diagnostici ufficiali di Fortinet per la tua versione FortiOS, verifica
  che: l'interfaccia di ricezione accetti RADIUS Accounting sulla porta
  configurata; il secret condiviso dell'agente RSSO corrisponda al `secret`
  di questo daemon; il mapping degli attributi endpoint/gruppo dell'agente
  RSSO corrisponda a [Dati inviati a FortiGate](#dati-inviati-a-fortigate);
  e che la firewall policy referenzi effettivamente il gruppo RSSO.

I comandi esatti di packet-capture, debug RADIUS e stato utenti autenticati
sono coperti dalla documentazione Fortinet (vedi i link in
[Passaggi post-installazione](#passaggi-post-installazione)) invece che
duplicati qui, perché è più probabile che restino accurati tra le release
FortiOS rispetto a una copia mantenuta in questo README.

### Sintomi comuni

| Sintomo | Lato probabile | Cosa verificare |
|---|---|---|
| `RADIUS timeout` nel log del daemon | FortiGate / rete | Ricezione accounting abilitata sull'interfaccia e porta corrette; routing/firewalling tra i due host |
| Il daemon logga `ok=True` ma su FortiGate non compare nulla | FortiGate | Secret condiviso e mapping attributi dell'agente RSSO |
| FortiGate mostra l'IP ma nessuna etichetta gruppo/utente | FortiGate | Mapping dell'attributo gruppo/contesto dell'agente RSSO |
| Le entry non spariscono mai dopo la disconnessione | FortiGate | Comportamento di flush sessione dell'agente RSSO |
| File di log non trovato all'avvio | Questo daemon / correlatore | Il correlatore (es. eduvpn-logger) non è ancora in esecuzione — il daemon riprova ogni 10s |

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
# poi aggiorna lo stesso secret sull'agente RSSO di FortiGate — vedi la
# documentazione Fortinet (link in "Passaggi post-installazione") per la
# tua versione FortiOS
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

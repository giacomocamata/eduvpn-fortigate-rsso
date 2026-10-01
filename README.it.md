# eduvpn-fortigate-rsso

*🇬🇧 [Read in English](README.md)*

**Identità utente delle sessioni WireGuard di [eduVPN](https://www.eduvpn.org/) su un FortiGate, tramite RADIUS Accounting (RSSO).**

Quando un server eduVPN inoltra il traffico dei client a un FortiGate senza NAT,
il FortiGate vede l'indirizzo di tunnel di ogni client (es. `10.20.0.5`) ma non
l'utente che c'è dietro: log e policy possono lavorare solo per pool di
indirizzi. Il **RADIUS Single Sign-On (RSSO)** di FortiGate colma questa lacuna:
impara le coppie *utente ↔ IP* dai pacchetti standard RADIUS
Accounting-Start/Stop (RFC 2866) inviati da un NAS.

`eduvpn-radius` è quel NAS. Segue il log di sessione scritto da
[eduvpn-logger](https://github.com/giacomocamata/eduvpn-logger) e trasforma ogni
`connect` in un Accounting-Start e ogni `disconnect` nell'Accounting-Stop
corrispondente:

```
eduvpn.log   2026-04-15T09:58:03.412871+02:00 event=connect user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" ...
  →  Accounting-Start  User-Name=alice  Framed-IP-Address=10.20.0.5  Framed-IPv6-Address=fd00:20::5  Called-Station-Id=staff  Acct-Session-Id=3f9c0a1be47d2c55

eduvpn.log   2026-04-15T11:02:57.731204+02:00 event=disconnect user=alice profile=staff device=ios conn=soAQTNO...= ...
  →  Accounting-Stop   User-Name=alice  Framed-IP-Address=10.20.0.5  Framed-IPv6-Address=fd00:20::5  Called-Station-Id=staff  Acct-Session-Id=3f9c0a1be47d2c55
```

È un daemon Python in un solo file (standard library + `pyrad`), in produzione
all'Università di Trieste accanto a eduvpn-logger.

## Come funziona

Le sessioni sono identificate dalla **public key WireGuard** (`conn`), la stessa
chiave usata da eduvpn-logger:

| Evento nel log | RADIUS | Note |
|---|---|---|
| `connect` | Accounting-Start | nuovo session id; se la stessa sessione viene annunciata di nuovo (eduvpn-logger lo fa dopo un proprio riavvio) lo Start viene re-inviato con lo stesso id, senza Stop |
| `connect`, stessa chiave, nuovo IP di tunnel | Stop, poi Start | la sessione vecchia viene chiusa prima |
| `connect` con un IP di tunnel tenuto da un'altra sessione | Stop per l'altra, poi Start | il pool ha riassegnato l'indirizzo: il disconnect dell'altra sessione è andato perso e la sessione è finita |
| `disconnect` | Accounting-Stop | stesso `Acct-Session-Id` dello Start |
| `roam` | nessuno | l'IP di tunnel non cambia, cambia solo l'indirizzo pubblico di provenienza |
| ogni `interim_interval` (1 h) | Interim-Update | per ogni sessione aperta: senza accounting il FortiGate dimentica un utente RSSO dopo il suo `rsso-context-timeout` (8 h di default) |
| `connect` con `user=-` o senza IP di tunnel | nessuno | nulla che il FortiGate possa usare |

Il daemon conserva le sessioni e la posizione raggiunta nel log in
`/var/lib/eduvpn-radius/state.json`:

- **Riavvii.** Allo stop invia un Accounting-Stop per ogni sessione aperta, così
  il FortiGate non tiene una coppia *utente ↔ IP* stantia mentre nessuno la
  aggiorna. All'avvio legge prima ciò che è stato scritto nel log mentre era
  fermo (anche attraverso una rotazione), poi re-invia l'Accounting-Start delle
  sessioni ancora aperte, con i loro session id originali.
- **FortiGate irraggiungibile.** Uno Start senza risposta viene ritentato ogni
  30 s finché il FortiGate risponde. Dopo un timeout i nuovi pacchetti non
  vengono inviati per 30 s, così un fermo non rallenta il log di 10 s per
  evento. Gli Stop non vengono ritentati (vedi [Limiti](#limiti)).
- **Rotazione del log.** Le rotazioni `create` e `copytruncate` vengono seguite
  per nome, e nessuna riga scritta a cavallo di una rotazione viene saltata.

## Requisiti

- Un server eduVPN con **[eduvpn-logger](https://github.com/giacomocamata/eduvpn-logger)**
  installato e attivo (o un altro strumento che scriva le stesse righe `event=`
  in `/var/log/eduvpn/eduvpn.log`).
- Linux con systemd, Python ≥ 3.9 e [`pyrad`](https://github.com/pyradius/pyrad)
  (`python3-pyrad` su Debian/Ubuntu, installato da `install.sh`).
- Un FortiGate con RSSO, raggiungibile su UDP 1813 dal server eduVPN. Testato
  con FortiOS 7.4.
- Un'architettura instradata (No-NAT): il FortiGate deve vedere gli indirizzi di
  tunnel come sorgente del traffico dei client, altrimenti la mappatura non ha
  nulla a cui applicarsi.

## Installazione

### 1. eduvpn-logger

Installare eduvpn-logger e verificare che, quando un client si connette, in
`/var/log/eduvpn/eduvpn.log` compaiano righe `connect` con l'utente e gli IP di
tunnel. eduvpn-radius legge solo quel file.

### 2. Installare il daemon

```bash
git clone https://github.com/giacomocamata/eduvpn-fortigate-rsso.git
cd eduvpn-fortigate-rsso
sudo ./install.sh
```

`install.sh` è idempotente e fa quanto segue:

| Elemento | Percorso |
|---|---|
| pacchetti | `python3`, `python3-pyrad` (nessun ripiego su pip: senza il pacchetto l'installer si ferma) |
| programma | `/usr/local/lib/eduvpn-radius/eduvpn-radius.py` e il suo `dictionary` RADIUS |
| unit systemd | `/etc/systemd/system/eduvpn-radius.service` |
| configurazione | `/etc/eduvpn-radius/eduvpn-radius.conf`, `0640`, solo se assente |
| stato | `/var/lib/eduvpn-radius` (creata da systemd, `0700`) |

Alla prima installazione la configurazione è un modello con valori segnaposto e
il servizio **non** viene avviato. Se una configurazione esiste già, viene
mantenuta e il servizio viene riavviato se è attivo (un servizio fermato o
disabilitato a mano resta com'è).

<details>
<summary>Installazione manuale (senza <code>install.sh</code>)</summary>

```bash
sudo apt install -y python3 python3-pyrad      # dnf su Fedora/EL
sudo install -d -m 0755 /usr/local/lib/eduvpn-radius
sudo install -m 0755 eduvpn-radius.py /usr/local/lib/eduvpn-radius/
sudo install -m 0644 dictionary /usr/local/lib/eduvpn-radius/
sudo install -m 0644 systemd/eduvpn-radius.service /etc/systemd/system/
sudo install -d -m 0750 /etc/eduvpn-radius
sudo install -m 0640 eduvpn-radius.conf.example /etc/eduvpn-radius/eduvpn-radius.conf
sudo systemctl daemon-reload
```

</details>

### 3. Configurare

```bash
sudo nano /etc/eduvpn-radius/eduvpn-radius.conf
```

Impostare `server` all'indirizzo del FortiGate a cui inviare i pacchetti RADIUS
e `secret` a un nuovo valore casuale (`openssl rand -base64 24`). Il daemon
rifiuta di partire finché il secret è ancora il segnaposto. Tutte le chiavi sono
descritte in [Configurazione](#configurazione).

### 4. Configurare il FortiGate

Il lato FortiGate si configura sul FortiGate stesso, con RSSO. Menu e comandi
cambiano tra le versioni di FortiOS, quindi non sono riportati qui. A livello
concettuale servono quattro cose:

1. **Accounting RADIUS accettato** sull'interfaccia rivolta al server eduVPN,
   sulla porta configurata (UDP 1813 di default).
2. **Un agente RSSO** con lo stesso shared secret di `eduvpn-radius.conf`,
   impostato per leggere l'indirizzo del client da `Framed-IP-Address` e il
   gruppo da `Called-Station-Id` (vedi [Attributi RADIUS](#attributi-radius)).
3. **Un gruppo utenti RSSO** che fa riferimento a quell'agente.
4. **Policy firewall** per i pool di indirizzi della VPN che usano quel gruppo,
   così che i loro log riportino il nome utente. Il gruppo può servire anche a
   filtrare gli accessi.

Vedere la documentazione Fortinet per la propria versione di FortiOS, ad es.
[Configuring RADIUS SSO authentication](https://docs.fortinet.com/document/fortigate/7.6.2/administration-guide/513092/configuring-radius-sso-authentication)
nella [Fortinet Document Library](https://docs.fortinet.com/).

### 5. Verifica

Per prima cosa verificare il percorso verso il FortiGate con una sessione di
prova: usare un indirizzo del pool VPN non in uso.

```bash
sudo /usr/local/lib/eduvpn-radius/eduvpn-radius.py --test 10.20.0.250
```

Invia un Accounting-Start per l'utente `eduvpn-radius-test`, attende INVIO (è il
momento di controllare che l'utente compaia nella lista utenti RSSO del
FortiGate), poi invia l'Accounting-Stop. Quindi avviare il servizio e connettere
un client:

```bash
sudo systemctl enable --now eduvpn-radius.service
sudo journalctl -u eduvpn-radius -f
```

Ogni sessione produce una riga `start(connect) user=… ok=True` e più tardi una
riga `stop(disconnect) … ok=True`. `ok=True` significa che il FortiGate ha
risposto.

| Sintomo | Causa probabile |
|---|---|
| `secret is not set (still the placeholder?)`, servizio fallito | passo 3 non eseguito |
| `RADIUS timeout`, `ok=False` | FortiGate non raggiungibile su UDP 1813 da questo host, accounting non accettato su quell'interfaccia, oppure **shared secret diverso** (il FortiGate scarta in silenzio i pacchetti con secret errato) |
| `ok=True` ma nessun utente sul FortiGate | impostazione degli attributi dell'agente RSSO (`Framed-IP-Address`, `Called-Station-Id`) |
| utente in lista ma assente da policy/log | la policy non usa il gruppo RSSO, oppure il traffico viene nattato prima del FortiGate |
| nessuna riga `start` | eduvpn-logger non scrive connect (passo 1), oppure `log_path` errato |
| `connect without tunnel IP ignored` | eduvpn-logger non ha potuto determinare l'indirizzo di tunnel di quella sessione |

## Configurazione

`/etc/eduvpn-radius/eduvpn-radius.conf` (INI). Dopo una modifica:
`sudo systemctl restart eduvpn-radius.service`.

| Sezione | Chiave | Default | Significato |
|---|---|---|---|
| `[radius]` | `server` | *(obbligatoria)* | indirizzo del FortiGate (IP o nome host) |
| `[radius]` | `port` | `1813` | porta RADIUS accounting |
| `[radius]` | `secret` | *(obbligatoria)* | shared secret, lo stesso dell'agente RSSO del FortiGate |
| `[radius]` | `nas_identifier` | nome host | `NAS-Identifier` di ogni pacchetto |
| `[radius]` | `interim_interval` | `3600` | secondi tra due Interim-Update; tenerlo ben sotto il `rsso-context-timeout` del FortiGate; `0` = disattivato |
| `[eduvpn]` | `log_path` | `/var/log/eduvpn/eduvpn.log` | log scritto da eduvpn-logger |
| `[eduvpn]` | `state_path` | `/var/lib/eduvpn-radius/state.json` | sessioni aperte e posizione nel log |

La unit viene sostituita a ogni reinstallazione. Per modificarla (es. un
percorso di configurazione diverso) usare un drop-in:
`sudo systemctl edit eduvpn-radius.service`.

## Attributi RADIUS

Ogni pacchetto è un Accounting-Request (UDP, porta 1813 di default) con:

| Attributo | Valore |
|---|---|
| `Acct-Status-Type` | `Start` (1), `Stop` (2) o `Interim-Update` (3) |
| `User-Name` | user ID eduVPN, come scritto da eduvpn-logger |
| `Framed-IP-Address` | indirizzo IPv4 di tunnel, se presente |
| `Framed-IPv6-Address` | indirizzo IPv6 di tunnel, se presente (RFC 6911) |
| `Called-Station-Id` | ID del profilo eduVPN, utilizzabile come gruppo RSSO |
| `Acct-Session-Id` | 16 caratteri esadecimali, uguale nello Start e nello Stop di una sessione |
| `NAS-Identifier` | `nas_identifier`, di default il nome host |
| `Acct-Delay-Time` | solo nelle ritrasmissioni (aggiunto da pyrad) |

Ogni pacchetto viene inviato al massimo due volte, attendendo 5 s
l'Accounting-Response del FortiGate; senza risposta il daemon registra
`ok=False`.

## Limiti

- **La mappatura è accurata quanto eduvpn-logger.** Le sessioni che chiude dopo
  180 s di silenzio negli handshake (disconnect dedotti) lasciano il FortiGate
  fino a 3 minuti dopo la fine reale del tunnel.
- **Gli Stop non vengono ritentati.** Uno Stop perso mentre il FortiGate è
  irraggiungibile lascia la coppia sul FortiGate finché l'indirizzo non viene
  riassegnato (il nuovo Start la sostituisce) o la voce scade sul FortiGate.
- **Un riavvio del FortiGate** svuota la sua tabella RSSO; le sessioni aperte
  tornano al connect successivo o con `systemctl restart eduvpn-radius`.
- **Mentre il daemon è fermo** il FortiGate non ha coppie per gli utenti VPN;
  all'avvio gli eventi arretrati vengono rigiocati. Un fermo che copre più di una
  rotazione del log perde gli eventi del file più vecchio, già compresso.
- **Primo avvio.** Le sessioni già aperte quando il daemon parte per la prima
  volta restano sconosciute finché non si riconnettono, o finché
  `systemctl restart eduvpn-logger` non le fa riannunciare da eduvpn-logger.

## Sicurezza e privacy

- **Shared secret.** La configurazione è `0640 root:root` in una directory
  `0750`. L'accounting RADIUS non è cifrato: i nomi utente viaggiano in chiaro
  verso il FortiGate, quindi quel percorso deve stare su una rete fidata.
- **Dati personali.** Il file di stato contiene user ID e relativi indirizzi di
  tunnel (directory `0700`). I log del FortiGate assoceranno il traffico agli
  utenti: definire finalità e conservazione con il proprio Responsabile della
  Protezione dei Dati.
- **Privilegi.** Il servizio gira come root dentro una sandbox systemd, senza
  capability, con i soli socket IPv4/IPv6/Unix e con `/usr`, `/boot` ed `/etc` in
  sola lettura. Verifica con `systemd-analyze security eduvpn-radius.service`.

## Aggiornamento e rimozione

Aggiornamento (configurazione e stato vengono mantenuti; il servizio viene
riavviato se è attivo):

```bash
cd eduvpn-fortigate-rsso && git pull && sudo ./install.sh
```

Il file di stato delle versioni precedenti viene letto così com'è.

Rimozione:

```bash
sudo systemctl disable --now eduvpn-radius.service
sudo rm -rf /usr/local/lib/eduvpn-radius /etc/eduvpn-radius /var/lib/eduvpn-radius \
    /etc/systemd/system/eduvpn-radius.service /etc/systemd/system/eduvpn-radius.service.d
sudo systemctl daemon-reload
```

Poi rimuovere agente RSSO, gruppo e riferimenti nelle policy sul FortiGate.

## Licenza

MIT, vedi [LICENSE](LICENSE).

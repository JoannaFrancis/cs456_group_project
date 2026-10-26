# CS456 Authentication and Ticket Critical Process

This implements the critical authentication process for Option A (push heartbeats).
Python 3.10 or later, standard library only; no pip installs. It validates dummy
credentials, issues random session tickets, validates tickets, and revokes them.
The UDP sender belongs inside this process so its beats stop when the process dies.
The independent heartbeat monitor is implemented with UDP reception, timeout based failure detect, and incident logging. The crash simulation and audit script remain in development by team members.

## Run on Windows PowerShell

Extract the ZIP, open a terminal in its `auth_ticket_service` folder. The heartbeat monitor run as an independent process and will listen for UDP heartbeat messages from our critical service while both are running.

Open a powershell terminal and run

```powershell
python monitor.py
```
Open a seperate PowerShell terminal then run:

```powershell
python critical_service.py --verbose
```

Leave that running. In another terminal in the same folder:

```powershell
python demo_client.py
```

On Linux/macOS replace `py` with `python3`. On Windows `python` also works if
installed on PATH. Ctrl+C stops the service. It runs even without a monitor.
The demo prints successful login/validation/logout, rejection of a revoked ticket,
and rejection of a wrong password. Tickets expire after 60 seconds by default.

Optional configuration (times are seconds):

```powershell
python critical_service.py --port 8000 --monitor-host 127.0.0.1 --monitor-port 9999 --heartbeat-interval 1 --ticket-ttl 60
```

## HTTP service contract

All operations are POST requests with a JSON object and Content-Length header.
Request bodies are limited to 4096 bytes. Credentials are `alice` / `alice-demo`
and `bob` / `bob-demo`.

| Endpoint | Request example | Success | Failure |
| --- | --- | --- | --- |
| `/login` | `{"username":"alice","password":"alice-demo"}` | 200 with `ticket`, `expires_in_seconds` | 401 wrong credentials; 503 ticket capacity |
| `/validate` | `{"ticket":"COPY_LOGIN_TICKET"}` | 200 with `valid: true`, `username` | 401 with `valid: false` |
| `/logout` | `{"ticket":"COPY_LOGIN_TICKET"}` | 200 with `revoked: true` | 401 invalid/expired ticket |

Malformed JSON/fields return 400; unknown POST paths return 404. The same ticket
can be validated repeatedly until expiration or logout. Tickets live in memory
and disappear at restart; expired entries are cleaned during ticket operations.
The store caps outstanding tickets at 1000. HTTP requests run sequentially with
3-second socket timeouts. This keeps the prototype small; it is not load resistant.

## Heartbeat Monitor Implementation

The independent monitor is implemented in monitor.py. It binds a UDP IPv4 socket to 127.0.0.1:9999 and recieves UTF-8 JSON heartbeat messages from the critical service.

The service sends one JSON object per datagram:

```json
{"type":"HEARTBEAT","service":"auth-ticket-service","instance_id":"uuid-per-startup","pid":1234,"sequence":1,"timestamp":1790000000.0}
```

`sequence` increases per attempted send and resets on process restart.
`timestamp` is Unix wall-clock seconds; `instance_id` changes each startup.

No credentials or tickets cross this channel. 

Default interval T = 1 second.

W = 3 seconds for the timeout window before flagging a failure.

Socket timeout = 1 second to allow monitor to check missing heartbeats.

The monitor uses its own reception time rather then the senders timestamp when evaluating failures to get mos accurate timing.

Detection: Uses an elapsed time since last valid heartbeat using time.monotonic(), rather then relying on specific individual missing packet counts

### Monitoring and fault detection

The monitor recives a UDP datagram and parses their JSON payloads. It checks that each payload is a dictionary and contains our expected heartbeat type and service ID.

When valid heartbeat arrives the monitor updates lastBeat and displays sequence number and reception time.

If 3 seconds pass without a valid heartbeat the monitor Prints a timestamped timeout alert, Records the incident in Heartbeat-Faults.log, and continues running and continues listening for incoming heartbeats.

The faultDetected flag will prevent repeated alerts during the same outage. This gets reset when a valid heartbeat is recieved and process goes back to normal flow.

The sender has its own thread so normal HTTP work does not interrupt beats.
A beat proves the sender is running, not that authentication is responsive:
a hung HTTP thread can coexist with a healthy sender. Document that limitation.

## Failure Simulation 

Once the critical ticketing service is up and running, if the --sim-leak argument is set to true, the memory leak simulator will cause a kernel shutdown. 
  
The memory leak simulator functions as follows : 
   - Initialize a separate thread to run the memory leak loop. This allows the simulation to function synchronously with the critical service without blocking
     requests on the main connection and heartbeat thread. 
   - A local byte array list is initialized outside the loop to avoid Python's garbage collector and a total-memory-leaked value is set to 0
   - While the stop_event is not set, the simulation will continually loop over the following :
        - Set a random delay and wait
        - set a random byte array chunk size and set a random byte in this array to 0xFF forcing the OS to commit the RAM to a physical page
        - append the chunk to the local byte array list
        - add amount appended to the total-memory-leaked value
        - check if total-memory-leaked is past the hard-coded memory leak budget. If so, add a critical failure message to the logger and utilize os.exit(1) to shutdown the whole kernel
           heartbeat and all.
   - Upon completion and failure, the kernel is shutdown and the heartbeats stop, forcing the monitor to hit a timeout error.

 The simulation generally runs and completes in around ~2 minutes.


## Handoff to adversarial audit owner

This baseline heartbeat is intentionally unauthenticated. The timestamp,
sequence, PID, UUID, and source address are metadata, not proof of authenticity.
A forged packet or replay may keep a naive monitor green after a crash.
Coordinate the monitor's validation rules with the audit owner; document observed
results. Sequence checks alone do not stop an attacker forging fresh sequences.
Optional hardening would require shared-key authentication and explicit freshness
and restart rules agreed on by both sender and monitor.

## Adversarial Audit

`heartbeat_audit.cpp` is an authorized localhost audit utility that demonstrates
heartbeat spoofing and replay attacks against the baseline monitor. It only sends
UDP datagrams to `127.0.0.1:9999`, the local monitor used by this prototype.

On Linux/Halibut, compile the audit utility with:

```bash
g++ -std=c++17 -Wall -Wextra -o heartbeat_audit heartbeat_audit.cpp

### Capture a legitimate heartbeat for replay

The monitor must be stopped because the capture utility temporarily listens on UDP port 9999.

1. Start the normal critical service:

   ```bash
   python critical_service.py --verbose
   ```

2. In a second terminal, capture one legitimate heartbeat:

   ```bash
   ./heartbeat_audit capture
   ```

This saves the received datagram unchanged to `captured_heartbeat.json`. Stop the normal critical service after capture with `Ctrl+C`.

### Demonstrate service failure

1. Start the monitor:

   ```bash
   python monitor.py
   ```

2. Start the critical service with simulated failure enabled:

   ```bash
   python critical_service.py --verbose --sim-leak true
   ```

3. After the critical service terminates, wait at least three seconds for the monitor to print and log its timeout alert.

### Heartbeat spoofing attack

After the critical service has crashed and the monitor has reported a timeout, send newly forged heartbeat messages:

```bash
./heartbeat_audit spoof --count 6 --interval 0.75
```

The baseline monitor accepts the forged heartbeat packets and clears its fault state even though the real critical service remains offline.

### Replay attack

After the monitor times out again, replay the previously captured legitimate heartbeat without changing its contents:

```bash
./heartbeat_audit replay --count 6 --interval 0.75
```

The baseline monitor accepts the stale heartbeat packet, including its old timestamp, sequence number, and instance ID, and treats the failed service as healthy.

### Audit findings and recommended mitigations

The baseline monitor checks only that an incoming JSON packet has the expected heartbeat type and service name. It does not authenticate the sender, validate timestamp freshness, enforce sequence progression, or verify that the `instance_id` belongs to the currently running service. As a result, an attacker can mask a service outage with both forged and replayed heartbeat packets.

A production design should use a message authentication code (HMAC) with a shared secret to detect spoofed or modified packets. It should also require authenticated timestamp freshness and/or a strictly increasing sequence number associated with the active service instance to reject replayed messages.

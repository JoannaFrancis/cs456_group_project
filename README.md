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
py monitor.py
```
Open a seperate PowerShell terminal then run:

```powershell
py critical_service.py --verbose
```

Leave that running. In another terminal in the same folder:

```powershell
py demo_client.py
```

On Linux/macOS replace `py` with `python3`. On Windows `python` also works if
installed on PATH. Ctrl+C stops the service. It runs even without a monitor.
The demo prints successful login/validation/logout, rejection of a revoked ticket,
and rejection of a wrong password. Tickets expire after 60 seconds by default.

Optional configuration (times are seconds):

```powershell
py critical_service.py --port 8000 --monitor-host 127.0.0.1 --monitor-port 9999 --heartbeat-interval 1 --ticket-ttl 60
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

## Handoff to failure simulation owner

Replace `start_failure_simulation(stop_event)` in `critical_service.py`.
It currently returns None and causes NO failures. Called once after startup;
it can return a started background Thread for shutdown cleanup.

Suggested bounded memory-leak model:

1. Add explicit CLI opt-in (for example `--simulate-leak`) and configurable budget.
2. In a worker, retain bytearray objects in a list so memory cannot be reclaimed.
3. Wait a random duration between allocations and allocate random block sizes.
   Example: 0.3–1.5 seconds and 128–512 KiB; touch allocated bytes.
4. Track retained bytes. At a modest budget such as 16 MiB, log the simulated
   exhaustion with flush enabled, then call `os._exit(1)` to end the entire process.
5. Use `stop_event.wait(delay)` to allow clean cancellation during ordinary shutdown.

This models progressive leakage and exhaustion without exhausting the host.
Random growth/waits make the crash timing unpredictable; do not use a fixed
request-count crash. Do not claim actual OS out-of-memory termination. Raising
an exception or calling `sys.exit()` in the worker only kills that thread and
leaves the heartbeat alive, so it does not meet the assignment's crash rule.
Ctrl+C is useful for development but is not the required stochastic failure.

## Handoff to adversarial audit owner

This baseline heartbeat is intentionally unauthenticated. The timestamp,
sequence, PID, UUID, and source address are metadata, not proof of authenticity.
A forged packet or replay may keep a naive monitor green after a crash.
Coordinate the monitor's validation rules with the audit owner; document observed
results. Sequence checks alone do not stop an attacker forging fresh sequences.
Optional hardening would require shared-key authentication and explicit freshness
and restart rules agreed on by both sender and monitor.

## Scope and limitations

This is a local classroom prototype using HTTP and hard-coded dummy passwords.
It is not Kerberos or a production authentication server. The audit
script is deliberately absent, and failure injection is an inactive documented
hook. The group still needs those implementations, CONTRIBUTIONS.md with real
names/contributions, report, and video. Review and understand the code, and
mention AI assistance in the individual reflection if you use it.

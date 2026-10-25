# collectors/

This directory is part of the required repository layout (master spec §30).
The collector implementations live next to the backend code they feed:

| collector | implementation | purpose |
|-----------|----------------|---------|
| packet | `backend/app/collectors/packet/` | live interface capture via scapy (metadata only; requires Npcap on Windows) |
| syslog | `backend/app/collectors/syslog/` | UDP syslog / firewall receiver (RFC 3164 + RFC 5424) |
| system | `backend/app/collectors/system/` | local host telemetry (psutil) |
| simulator | `backend/app/collectors/network/synthetic.py` | authorized-lab event generator (off unless `MINI_SOC_SIMULATOR_ENABLED=true`) |

All collectors push `RawRecord`s into the bounded pipeline queue; they never
touch the database directly (single-writer design). Selection and tuning happen
through `MINI_SOC_COLLECTOR_*` settings — see [.env.example](../.env.example).

Mini SOC ships **real-time only**: packet capture, the syslog receiver and host
telemetry are the only sources attached at start-up. The lab generator is
disabled by default, is refused by `POST /system/simulator` while disabled, and
its offline harnesses (`scripts/lab_validation.py`, `scripts/benchmark_pipeline.py`)
write to their own throw-away databases so they never pollute the live SOC.

Run and configuration details: [docs/architecture](../docs/architecture/README.md)
and [docs/deployment](../docs/deployment/README.md).

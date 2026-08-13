# Legacy Two-Node Stability Collection

## Scope

This evidence collects the historical work directories named as a 24-hour
runtime stability run. It predates the three-compute Heartbeat V2 image
acceptance and must not be combined with the fresh 12-hour Heartbeat V2 soak.

## Disposition

The run is `interrupted`, not `pass`:

- no process remains;
- no exit-code file exists;
- no `trend-summary.txt` exists;
- no `runtime_stability_soak=pass` marker exists;
- compute 2 contains 47 samples and compute 4 contains 48 samples at a
  five-minute interval, approximately four hours rather than 24 hours.

No product error, OOM event, reboot, or runtime identity failure was recorded
at the end of either log. The two monitors ended about five minutes apart. The
available evidence cannot identify the external stop cause, so it is recorded
as `interrupted_external_or_unknown`.

## Observed Short-Term Trends

| Metric | Compute 2 | Compute 4 |
| --- | ---: | ---: |
| Samples | 47 | 48 |
| Observed duration | 13,843 s | 14,139 s |
| Managed ports | 23 to 23 | 14 to 14 |
| Generation | unchanged | unchanged |
| Accepted equals applied | all samples | all samples |
| Pending generation | none | none |
| Overall readiness | ready in all samples | ready in all samples |
| Agent RSS delta | +144 KiB | +120 KiB |
| Datapath RSS delta | +44 KiB | 0 KiB |
| Agent FD delta | 0 | 0 |
| Datapath FD delta | 0 | 0 |
| Agent/datapath thread delta | 0 / 0 | 0 / 0 |
| WAL byte/file delta | 0 / 0 | 0 / 0 |
| Pinned file delta | 0 | 0 |

Compute 4 recorded two transient datapath samples with increased RSS and file
descriptors. Both returned to baseline at the next sample and did not produce
readiness, generation, WAL, thread, or pinned-object drift. This is not a
monotonic leak signal, but the interrupted window is too short for a long-term
stability conclusion.

The monitor checks container/process identity and the OVS/Neutron OVS agent
identity before every recorded sample. Those checks did not fail during the
observed interval. Current Python agent identities are intentionally different
because Heartbeat V2 was deployed after this historical run.

## Next Action

Do not advance the automation's conditional multi-port scale gate from this
run. Start a fresh uninterrupted Heartbeat V2 soak tonight with PID and exit
code capture, then evaluate its trend summary and cleanup/rollback evidence.

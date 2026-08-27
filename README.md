# Personal Operations Readiness v0.2

`personal_ops_readiness.py` is a deterministic, read-only status checker for
this workstation. It prints a concise Markdown report by default and can emit
machine-readable JSON.

## Checks

- capacity for the workstation root/home and existing monitored storage paths:
  `/srv/storage`, `/srv/disk6`, `/srv/disk12`, and `/srv/lexar`;
- live SMART health when directly readable, safe sysfs NVMe temperatures/device
  state, and separately labelled historical `smartd` alerts;
- systemd completion evidence for `archive-critical-backup.service` and
  `proton-backup.service`, compared with their local status artifacts;
- user timer definitions, enablement links, and runtime state when the user
  systemd bus is accessible;
- known active Git worktrees under `~/Projects` plus the Obsidian `Aktif Kasa`
  worktree.

It does not inspect finance, vault note content, career data, or media metadata.
It does not run backups or SMART tests and does not remediate findings.

## Run

```bash
cd /home/savpavi/Projects/personal-ops-readiness
python3 personal_ops_readiness.py --markdown
python3 personal_ops_readiness.py --json
python3 -m unittest -v test_readiness.py
```

The default output is Markdown, so `--markdown` is optional. Redirecting output
to a file is a caller-controlled write; the checker itself never writes a
report or state file.

## Severity and exit codes

Storage thresholds are `<85% GREEN`, `85–89% YELLOW`, `90–94% ORANGE`, and
`>=95% RED`. ORANGE is a `WARNING`; RED is `CRITICAL`. A filesystem at 94%
also reports `CAPACITY ACTION SOON` and its one-percentage-point headroom to
RED. The checker does not predict an exhaustion date without trend data.

Overall status:

- `RED`: at least one current `CRITICAL` condition;
- `YELLOW`: no critical condition, but a meaningful `WARNING` exists;
- `GREEN`: no meaningful current warning and essential checks succeeded;
- `UNKNOWN`: no warning or critical condition, but an essential check could
  not be completed.

Exit codes are stable: `0` for GREEN, `1` for YELLOW or UNKNOWN, and `2` for
RED. Historical SMART temperature alerts are informational and are not treated
as proof of current hardware failure.

## Safety guarantees

The checker invokes only read-only status commands (`findmnt`, `df`, `lsblk`,
`smartctl -a`, `systemctl --user show`, and read-only Git commands). It never
starts or stops services, modifies timers or mounts, runs a SMART test, performs
a backup, restores or prunes data, or changes a Git worktree. Git filenames,
raw process arguments, credentials, environment-file contents, and command
stderr are not included in reports.

Missing permissions, an inaccessible systemd bus, or absent success evidence
produce `UNKNOWN`, not a fabricated failure or success.

Timer trigger time is never treated as backup success. A backup is successful
only when service completion evidence or an unambiguous job artifact proves
it. If systemd and a local status artifact disagree, both are retained in the
report and the disagreement is a warning; the checker does not rewrite either.

## Optional manual SMART diagnostic

The normal checker never invokes `sudo`. If an administrator intentionally
wants a one-off live diagnostic outside the checker, the read-only command is:

```bash
sudo smartctl -a /dev/DEVICE
```

Replace `DEVICE` explicitly after checking `lsblk`; do not use a guessed device
or add this command to the scheduled checker. This reads SMART data but does
not start a short or long SMART test.

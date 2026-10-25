# tinyvault

A single-admin vault for application secrets, grouped by project and environment, that can export them or push them to remote hosts over SSH.

## Secrets

**Project**:
A named group of environments belonging to one application.
_Avoid_: App, namespace

**Environment**:
A named set of keys within a project, such as prod or staging.
_Avoid_: Stage, env group

**Key**:
A named secret inside an environment. Its value is stored encrypted and bound to its project, environment and name.
_Avoid_: Variable, entry, secret name

**Version**:
One immutable revision of a key's value. Every set, rollback and delete adds a new version.
_Avoid_: Revision

**Tombstone**:
A version that marks a key as deleted while keeping its history.
_Avoid_: Soft delete

**Reference**:
A `${KEY}` placeholder in a value that points to another key in the same environment.
_Avoid_: Variable, interpolation

**Reference resolution**:
Replacing every reference in an environment with the value it points to, failing on unknown keys or cycles.
_Avoid_: Expansion, interpolation

**Format**:
A file layout that an environment can be exported to or imported from: dotenv, JSON, shell or Kubernetes Secret.
_Avoid_: Output type, encoding

**Export**:
Decrypting every key in an environment and rendering it in a format. Always recorded in the audit log.
_Avoid_: Dump, download

## Delivery

**Target**:
A file on a host that one environment is pushed to, with its format, whether references are resolved, and an optional post-command.
_Avoid_: Destination, deployment

**Host**:
A remote machine that targets point at, with its SSH user, address and host key pin. Shared by targets across projects.
_Avoid_: Server, node, remote

**Push**:
Writing an environment's export to a target's file over SSH, then running its post-command.
_Avoid_: Deploy, sync, upload

**Check**:
Comparing a target's remote file with the current export and the last push, producing a status.
_Avoid_: Verify, diff

**Status**:
The result of a check: in sync, pending, drifted, missing or never pushed.
_Avoid_: State

**Host key pin**:
The SSH host key recorded on first connection and required on every later one.
_Avoid_: Known host, fingerprint

**Post-command**:
A shell command run on the host after a successful file write.
_Avoid_: Hook, script

## Oversight

**Actor**:
Who performed an action, recorded on versions and audit entries.
_Avoid_: User, author

**Audit entry**:
A record of one action: when, by which actor, what action, on what, and detail.
_Avoid_: Log line, event

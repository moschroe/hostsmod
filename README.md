# Hostsmod - safely modify `/etc/hosts`

Command line tool for modifying hosts file on Linux/UNIX to change static hostname-IP mappings.

Intended to be run with the suid bit set, so unprivileged users may update the hosts file. This
allow easy integration for jobs like updating entries after launching a docker container or
locally testing virtual hosts vor web projects without any requirement for privilege escalation.

## Engineered for Safety

The tool has been engineered for safety and features a configurable list of hostnames for which
entries may be modified. No other modifications are allowed.

Also, some key entries that might affect correct function of software like `localhost` are
checked before writing the new configuration.

The new configuration is written to the file system under a different name next to the original
file and only moved into place as the last step. This makes the change atomic (according to
POSIX semantics) and any error occurring earlier leaves the existing configuration intact. After
an unsuccessful run, if the new placeholder file is already present, manual intervention will
be necessary.

## Configuration

Run with `--sample-config` to generate a sample YAML config which can be placed at `/etc/hostsmod.yaml`. Take care to
make this file only modifiable (or even accessible) to the root user if arbitrary modifications should be prohibited.
The executable then has to be granted the suid bit, which can be done by `sudo chmod u+s <path-to-hostsmod>` and has to
be owned by the root user.

## Examples

Run with `--help` to get an extensive description of what the software does and how it is controlled.

Remove entry so the deployed instance can be accessed (observe `--` to differentiate from flags):

```shell
hostsmod -- -prod.project.tld
```

Add entries so a local dev environment can be tested using real-world hostnames:

```shell
hostsmod -- 127.0.0.1=prod.project.tld ::1+=prod.project.tld 127.0.0.1=assets.project.tld
```

Add entry for random IP of temporary dev system:

```shell
hostsmod "$(docker inspect --format '{{ .NetworkSettings.Networks.svc.IPAddress }}' localdb)=database"
```
# fastsmtp-cli

The remote CLI client for [FastSMTP](https://github.com/jsenecal/fastsmtp), an async SMTP
server that forwards received email to webhooks.

This package talks to a running FastSMTP server over its HTTP API. It does not import or
depend on the server package, so it installs cleanly on a workstation with none of the
server's dependencies.

## Install

```bash
pip install fastsmtp-cli
```

The command is `fsmtp`.

## Use

```bash
fsmtp config set default --url https://smtp.example.com --api-key <key>

fsmtp domain list
fsmtp domain create example.com
fsmtp recipient create <domain-id> https://hooks.example.com/support --local support
fsmtp ops log list <domain-id> --status failed
```

Profiles are stored in a config file, so several servers can be addressed from one machine
with `--profile`. `fsmtp config init` sets the first one up interactively.

## Documentation

Command reference and examples: <https://jsenecal.github.io/fastsmtp/cli/fsmtp/>.

Source and issue tracker: <https://github.com/jsenecal/fastsmtp>.

## License

AGPL-3.0-or-later - this program is free software: you can redistribute it and/or
modify it under the terms of the GNU Affero General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).

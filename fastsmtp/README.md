# FastSMTP

A TLS-capable, async SMTP server that receives email, verifies DKIM and SPF, and forwards
the contents to configurable webhooks. Built for Python 3.12+ and for integration with n8n
and other webhook-based workflow platforms.

This is the server package. The remote CLI client is a separate distribution,
[`fastsmtp-cli`](https://pypi.org/project/fastsmtp-cli/), which talks to a running server
over HTTP and does not depend on this one.

## Install

```bash
pip install fastsmtp
```

On Alpine and other musl-based distributions, note that `google-re2` publishes manylinux
wheels but no musllinux wheels, so pip has to build it: install a compiler and the RE2
library first, or use the container image instead.

Container images are published to
[ghcr.io/jsenecal/fastsmtp](https://github.com/jsenecal/fastsmtp/pkgs/container/fastsmtp).

## Run

```bash
export FASTSMTP_DATABASE_URL=postgresql+asyncpg://user:pass@localhost/fastsmtp
export FASTSMTP_ROOT_API_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

fastsmtp db upgrade head   # apply migrations first, every time
fastsmtp serve
```

Configuration is read from `FASTSMTP_*` environment variables and from a `.env` file in the
working directory. Migrations are never applied automatically: run `fastsmtp db upgrade head`
before starting a newer version, or the server refuses to start against a database behind it.

## Documentation

Full documentation, including the configuration reference, the HTTP API and the rules
engine, is at <https://jsenecal.github.io/fastsmtp/>.

Source and issue tracker: <https://github.com/jsenecal/fastsmtp>.

## License

AGPL-3.0-or-later - this program is free software: you can redistribute it and/or
modify it under the terms of the GNU Affero General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).

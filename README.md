# MineOS-Market-Server
Python MineOS App Market Server Reimplementation

[![Tests](https://github.com/CoolCat467/MineOS-Market-Server/actions/workflows/tests.yml/badge.svg)](https://github.com/CoolCat467/MineOS-Market-Server/actions/workflows/tests.yml)
<!-- BADGIE TIME -->

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/CoolCat467/MineOS-Market-Server/main.svg)](https://results.pre-commit.ci/latest/github/CoolCat467/MineOS-Market-Server/main)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)
[![code style: black](https://img.shields.io/badge/code_style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

<!-- END BADGIE TIME -->

## Description
Python re-implementation of the server side of the MineOS App Market

## Installation
Ensure Python 3 is installed on your computer, and use pip to
install this project with the command listed below:

```console
pip install git+https://github.com/CoolCat467/MineOS-Market-Server.git
```

## Configuration
Configuration file locations follow the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html).
Main configuration file lives at `$XDG_CONFIG_HOME/mineos_market_webserver/config.toml`, or `$HOME/.local/share/mineos_market_webserver/config.toml` if unset.
In the main configuration file you can change things like what port(s)
the webserver is hosted on, hypercorn configuration, and enabling
SSL support!


## Usage
Run the server:
```console
mineos_market_server
```
Go to URL `http://<IP_of_host>:3004`


## Enabling SSL Support
If you would like to enable SSL support on the local network, it's a bit
tricky but it's doable, successfully tested in production, and completely free!
1) Make sure your internet router is set to have the machine running
the webserver to have a static ip address. This does not need to be
a publicly accessible ip address.
2) Create a free account with [duckdns](https://www.duckdns.org/)
3) Add a domain with a name of your choice and set the ip to the static ip
address of the machine running the webserver.
4) Install certbot on the machine running the webserver.
(https://certbot.eff.org/instructions)
When it asks `software`, tell them `other`.
For my installation, I ended up [installing it with pip](https://pypi.org/project/certbot/).
5) Install the [certbot duckdns plugin](https://github.com/infinityofspace/certbot_dns_duckdns) for certbot
6) Either run certbot from duckdns plugin's README or run [/scripts/cert_create.sh](https://github.com/CoolCat467/MineOS-Market-Server/blob/scripts/cert_create.sh) with your details.
7) Setup autorenewal from [certbot wiki](https://eff-certbot.readthedocs.io/en/latest/using.html#setting-up-automated-renewal) or look at [/scripts/cert_renew.sh](https://github.com/CoolCat467/MineOS-Market-Server/blob/scripts/cert_renew.sh)
8) Uncomment SSL lines in the webserver configuration file (see section above) and edit as needed for your particular setup.

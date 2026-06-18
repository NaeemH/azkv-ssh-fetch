# azkv-ssh-fetch

[![CI](https://github.com/NaeemH/azkv-ssh-fetch/actions/workflows/ci.yml/badge.svg)](https://github.com/NaeemH/azkv-ssh-fetch/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/azkv-ssh-fetch.svg)](https://pypi.org/project/azkv-ssh-fetch/)
[![Python](https://img.shields.io/pypi/pyversions/azkv-ssh-fetch.svg)](https://pypi.org/project/azkv-ssh-fetch/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> Fetch SSH private keys from **Azure Key Vault** and connect to VMs / VMSS instances through **Azure Bastion** — in one command.

`azkv-ssh-fetch` (alias `akf`) wraps the boring half of the operator workflow:

1. Authenticate via `DefaultAzureCredential` (env vars → managed identity → `az login`).
2. Pull the named private key from a Key Vault.
3. Write it to `~/.ssh/<name>` with mode `0600` (atomic replace, parent dir tightened to `0700`).
4. Shell out to `az network bastion ssh` with the right flags.
5. Optionally shred the key on disconnect.

## Why this exists

If your operating model says "private keys live in Key Vault, humans get to them through RBAC, and the only path to the VM is through Bastion" — then operators end up running the same 6-line shell snippet over and over. This packages that snippet, types it, tests it, and removes the foot-guns (wrong perms, stale keys lingering in `/tmp`, mis-typed resource IDs).

## Install

```bash
pipx install azkv-ssh-fetch
# or
pip install --user azkv-ssh-fetch
```

Requires Python 3.10+ and the `az` CLI on `PATH` for the `connect` subcommand.

## Quick start

```bash
# 1. List SSH-shaped secrets in a vault
akf list --vault pro-zks1-nagios-kv

# 2. Pull a key to ~/.ssh/nagios-ssh (mode 600, atomic)
akf fetch --vault pro-zks1-nagios-kv nagios-ssh

# 3. Fetch + Bastion SSH in one shot
akf connect \
  --vault pro-zks1-nagios-kv \
  --secret nagios-ssh \
  --bastion my-bastion \
  --bastion-rg my-bastion-rg \
  --target-id "/subscriptions/.../virtualMachineScaleSets/zks1-nagios/virtualMachines/0" \
  --username azureuser
```

## Configuration

| Variable      | Meaning                                                       |
| ------------- | ------------------------------------------------------------- |
| `AZKV_VAULT`  | Default Key Vault name (overridden by `--vault`).             |
| `AZKV_DEBUG`  | Set to `1` for verbose `azure-identity` logging on stderr.    |
| Standard `AZURE_*` env vars are honored by `DefaultAzureCredential`. |

## Subcommands

### `list`

Show enabled secrets in the vault whose names look like SSH keys (match `ssh`, `key`, `id_rsa`, `id_ed25519`). Exits `1` if none found, `2` on access errors.

### `fetch`

Pull a single secret and write it to disk.

```
Usage: akf fetch [OPTIONS] SECRET

  Pull SECRET from VAULT and write it locally (chmod 600).

Options:
  -v, --vault TEXT         Key Vault name. [env: AZKV_VAULT; required]
  -o, --output PATH        Destination path. Default: ~/.ssh/<secret>.
```

### `connect`

Fetch the key, open a Bastion SSH session, and (unless `--keep-key`) remove the key file on disconnect.

```
Usage: akf connect [OPTIONS]

Options:
  -v, --vault TEXT          Key Vault name. [env: AZKV_VAULT; required]
  -s, --secret TEXT         KV secret name. [required]
  -b, --bastion TEXT        Bastion name. [required]
      --bastion-rg TEXT     Bastion's resource group. [required]
  -t, --target-id TEXT      Full ARM resource ID of target VM or VMSS instance. [required]
  -u, --username TEXT       SSH username on the target. [default: azureuser]
      --keep-key/--shred-key
                            Leave the key on disk after disconnect. [default: shred-key]
```

## Security notes

- **Always 0600.** Keys are written through a sibling tempfile with `0600` set via `fchmod` *before* any bytes touch disk, then atomically renamed.
- **No shell interpolation.** The `az` invocation is a fixed `argv` list — no `shell=True`.
- **Key shredding.** `connect` removes the on-disk copy on disconnect by default. Pass `--keep-key` to retain it.
- **Trust chain.** Auth uses `DefaultAzureCredential`; nothing custom about token handling.

## Development

```bash
git clone https://github.com/NaeemH/azkv-ssh-fetch
cd azkv-ssh-fetch
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
pytest
ruff check . && ruff format --check .
mypy src
```

## License

[MIT](LICENSE) © 2026 Naeem Hossain

## smartscanner — Next-Gen Smart Contract Vulnerability Scanner (Solidity & Go/Fabric)

Work-in-progress CLI scanning engine written in Go. This is an initial scaffold to iterate on.

Build:

```
go build -o smartscanner ./cmd/nuclei
```

Run help:

```
./smartscanner --help

GitHub Action (SARIF upload) example is in `.github/workflows/smartscanner.yml`.

TUI keys:
- Arrow keys or h/j/k/l to navigate
- s: cycle severity filter; r: toggle rule filter; i: inline suppression hint; q: quit
```



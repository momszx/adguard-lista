# adguard-lista

One merged, deduplicated DNS blocklist for AdGuard Home, built from public lists.

Use this URL as a DNS blocklist in AdGuard Home (Filters, DNS blocklists, Add a blocklist):

    https://raw.githubusercontent.com/momszx/adguard-lista/main/blocklist.txt

## How it works

- `sources.txt` holds one source URL per line.
- `main.go` downloads them, keeps only plain domain rules (`||domain^`, hosts lines, bare domains),
  honours simple `@@||domain^` allow rules, drops subdomains already covered by a blocked parent
  domain, and writes `blocklist.txt`.
- Rules with modifiers, wildcards or regexes are skipped on purpose.
- If any source fails to download, or the result is smaller than 50000 domains, nothing is written,
  so a broken source never shrinks the published list.
- A GitHub Actions workflow rebuilds the list daily and on changes to the code or sources.

## Local run

    go test ./...
    go run . -sources sources.txt -out blocklist.txt

The list contains public data only. No LAN names or secrets.

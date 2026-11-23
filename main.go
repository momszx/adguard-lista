// Command adguard-lista merges public DNS blocklists into one deduplicated AdGuard Home list.
//
// It reads source URLs from sources.txt, keeps only plain domain rules, drops domains
// that are already covered by a blocked parent domain, honours simple allow rules, and
// writes blocklist.txt. Any download error aborts the run so a broken source never
// shrinks the published list.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxBody = 64 << 20 // 64 MiB per source

// shortcut: minimum size guard is a fixed number, raise it if the chosen sources shrink for good.
const minDomains = 50000

var domainRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$`)

var ipTLD = regexp.MustCompile(`\.[0-9]+$`)

func validDomain(d string) bool {
	return len(d) <= 253 && domainRe.MatchString(d) && !ipTLD.MatchString(d)
}

// parseLine returns the domain of a simple rule. allow is true for @@||domain^ rules.
// Anything with modifiers, wildcards, paths or regexes is ignored on purpose.
func parseLine(line string) (domain string, allow bool, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
		return "", false, false
	}
	if rest, found := strings.CutPrefix(line, "@@||"); found {
		d, found := strings.CutSuffix(rest, "^")
		d = strings.ToLower(d)
		if found && validDomain(d) {
			return d, true, true
		}
		return "", false, false
	}
	if rest, found := strings.CutPrefix(line, "||"); found {
		d, found := strings.CutSuffix(rest, "^")
		d = strings.ToLower(d)
		if found && validDomain(d) {
			return d, false, true
		}
		return "", false, false
	}
	if i := strings.Index(line, "#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	f := strings.Fields(line)
	switch {
	case len(f) == 1:
		d := strings.ToLower(f[0])
		if validDomain(d) {
			return d, false, true
		}
	case len(f) >= 2 && (f[0] == "0.0.0.0" || f[0] == "127.0.0.1"):
		d := strings.ToLower(f[1])
		if validDomain(d) && d != "localhost" {
			return d, false, true
		}
	}
	return "", false, false
}

// parents returns d itself and every parent domain that still has at least two labels.
func parents(d string) []string {
	out := []string{d}
	for {
		i := strings.Index(d, ".")
		if i < 0 {
			break
		}
		d = d[i+1:]
		if !strings.Contains(d, ".") {
			break
		}
		out = append(out, d)
	}
	return out
}

// merge drops blocked domains that are allowed (or under an allowed domain) and
// domains whose parent is already blocked. The result is sorted.
func merge(block, allow map[string]bool) []string {
	var out []string
	for d := range block {
		keep := true
		for _, p := range parents(d) {
			if allow[p] {
				keep = false
				break
			}
		}
		if keep {
			for _, p := range parents(d)[1:] {
				if block[p] {
					keep = false
					break
				}
			}
		}
		if keep {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

func fetch(client *http.Client, url string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "adguard-lista-builder")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var lines []string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxBody))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func readSources(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var urls []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			urls = append(urls, l)
		}
	}
	return urls, nil
}

func main() {
	srcPath := flag.String("sources", "sources.txt", "file with one source URL per line")
	outPath := flag.String("out", "blocklist.txt", "output list")
	flag.Parse()

	urls, err := readSources(*srcPath)
	if err != nil || len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "no sources:", err)
		os.Exit(1)
	}
	client := &http.Client{Timeout: 90 * time.Second}
	block, allow := map[string]bool{}, map[string]bool{}
	failed := false
	for _, u := range urls {
		lines, err := fetch(client, u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", u, err)
			failed = true
			continue
		}
		n := 0
		for _, l := range lines {
			if d, isAllow, ok := parseLine(l); ok {
				n++
				if isAllow {
					allow[d] = true
				} else {
					block[d] = true
				}
			}
		}
		fmt.Printf("%7d rules  %s\n", n, u)
	}
	if failed {
		fmt.Fprintln(os.Stderr, "at least one source failed, output not written")
		os.Exit(1)
	}
	list := merge(block, allow)
	if len(list) < minDomains {
		fmt.Fprintf(os.Stderr, "only %d domains, below the %d guard, output not written\n", len(list), minDomains)
		os.Exit(1)
	}
	var b strings.Builder
	b.WriteString("! Title: adguard-lista\n")
	b.WriteString("! Merged and deduplicated from public lists, see sources.txt\n")
	fmt.Fprintf(&b, "! Domains: %d\n", len(list))
	for _, d := range list {
		b.WriteString("||" + d + "^\n")
	}
	if err := os.WriteFile(*outPath, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%d domains written to %s\n", len(list), *outPath)
}

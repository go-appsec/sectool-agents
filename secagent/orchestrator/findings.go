package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/secagent/util"
)

var findingIndexRe = regexp.MustCompile(`^finding-(\d+)-.*\.md$`)
var unvalidatedIndexRe = regexp.MustCompile(`^unvalidated-(\d+)-.*\.md$`)

var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true,
}

// CanonicalEndpoint returns endpoint lowercased with method prefix and
// query string stripped, and numeric path segments rewritten to :id.
func CanonicalEndpoint(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	s := strings.TrimSpace(endpoint)
	fields := strings.SplitN(s, " ", 2)
	if len(fields) == 2 && httpMethods[strings.ToUpper(fields[0])] {
		s = fields[1]
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimRight(s, "/")

	parts := strings.Split(s, "/")
	for i, p := range parts {
		if _, err := strconv.ParseUint(p, 10, 64); err == nil {
			parts[i] = ":id"
		}
	}
	return strings.Join(parts, "/")
}

// TitlesSimilar reports whether a and b's slugs match exactly, are
// substrings of each other, or share more than half their slug words.
func TitlesSimilar(a, b string) bool {
	sa, sb := util.Slugify(a), util.Slugify(b)
	if sa == "" || sb == "" {
		return false
	}
	if sa == sb || strings.Contains(sa, sb) || strings.Contains(sb, sa) {
		return true
	}
	notEmpty := func(s string) bool { return s != "" }
	wa := bulk.SliceToSet(bulk.SliceFilter(notEmpty, strings.Split(sa, "-")))
	wb := bulk.SliceToSet(bulk.SliceFilter(notEmpty, strings.Split(sb, "-")))
	if len(wa) == 0 || len(wb) == 0 {
		return false
	}
	var overlap int
	for w := range wa {
		if _, ok := wb[w]; ok {
			overlap++
		}
	}
	return float64(overlap)/float64(max(len(wa), len(wb))) > 0.5
}

// MatchTier reports which rule matched a pending candidate to a filed finding.
type MatchTier int

const (
	MatchNone MatchTier = iota
	// MatchTitleAndEndpoint is title similar AND endpoint canonical-equal.
	MatchTitleAndEndpoint
	// MatchEndpointOnly is same canonical endpoint, titles diverge.
	MatchEndpointOnly
	// MatchTitleOnly is similar title, endpoints diverge or one is missing.
	MatchTitleOnly
)

// String returns a short label for logging.
func (t MatchTier) String() string {
	switch t {
	case MatchTitleAndEndpoint:
		return "title+endpoint"
	case MatchEndpointOnly:
		return "endpoint-only"
	case MatchTitleOnly:
		return "title-only"
	}
	return "none"
}

// MatchPendingCandidates returns pending candidate IDs that match filed.
// Prefer MatchPendingCandidatesTiered when the matching tier is needed.
func MatchPendingCandidates(filed FindingFiled, pending []FindingCandidate) []string {
	ids, _ := MatchPendingCandidatesTiered(filed, pending)
	return ids
}

// MatchPendingCandidatesTiered returns the first non-empty match of pending
// candidates to filed using progressively looser rules: title+endpoint,
// endpoint-only, then title-only. Returns (nil, MatchNone) when no tier matches.
func MatchPendingCandidatesTiered(filed FindingFiled, pending []FindingCandidate) ([]string, MatchTier) {
	if filed.Title == "" && filed.Endpoint == "" {
		return nil, MatchNone
	}
	filedEP := CanonicalEndpoint(filed.Endpoint)

	if filedEP != "" && filed.Title != "" {
		var out []string
		for _, c := range pending {
			if CanonicalEndpoint(c.Endpoint) == filedEP && TitlesSimilar(c.Title, filed.Title) {
				out = append(out, c.CandidateID)
			}
		}
		if len(out) > 0 {
			return out, MatchTitleAndEndpoint
		}
	}

	if filedEP != "" {
		var out []string
		for _, c := range pending {
			if CanonicalEndpoint(c.Endpoint) == filedEP {
				out = append(out, c.CandidateID)
			}
		}
		if len(out) > 0 {
			return out, MatchEndpointOnly
		}
	}

	if filed.Title != "" {
		var out []string
		for _, c := range pending {
			if TitlesSimilar(c.Title, filed.Title) {
				out = append(out, c.CandidateID)
			}
		}
		if len(out) > 0 {
			return out, MatchTitleOnly
		}
	}

	return nil, MatchNone
}

// FindingWriter persists verified findings.
type FindingWriter struct {
	mu          sync.Mutex
	findingsDir string
	// Count is the highest finding-NN-*.md sequence on disk.
	Count int
	// UnvalidatedCount is the highest unvalidated-NN-*.md sequence on disk.
	UnvalidatedCount int
	// RunCount counts findings filed in this process only.
	RunCount int
	Paths    []string
	index    []findingIndexEntry
}

// findingIndexEntry records one written finding. titleSlug and endpoint are cached for fast dedup matching.
type findingIndexEntry struct {
	filed     FindingFiled
	titleSlug string
	endpoint  string
	path      string
}

// SimilarFinding is a previously written finding whose title is similar
// enough to a new filing to warrant LLM dedup review.
type SimilarFinding struct {
	Filed FindingFiled
	Path  string
}

// NewFindingWriter returns a FindingWriter for findingsDir. Count and
// UnvalidatedCount are seeded from existing files in the directory.
func NewFindingWriter(findingsDir string) *FindingWriter {
	index, count := loadExistingFindingIndex(findingsDir)
	unvalidated := loadExistingUnvalidatedMax(findingsDir)
	return &FindingWriter{
		findingsDir:      findingsDir,
		Count:            count,
		UnvalidatedCount: unvalidated,
		index:            index,
	}
}

// loadExistingUnvalidatedMax returns the highest unvalidated-NN-*.md sequence in findingsDir, or 0 if none.
func loadExistingUnvalidatedMax(findingsDir string) int {
	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		return 0
	}
	var max int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := unvalidatedIndexRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		if n > max {
			max = n
		}
	}
	return max
}

func loadExistingFindingIndex(findingsDir string) ([]findingIndexEntry, int) {
	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		return nil, 0
	}
	type diskFinding struct {
		seq   int
		entry findingIndexEntry
	}

	var max int
	var loaded []diskFinding
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := findingIndexRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		if n > max {
			max = n
		}
		path := filepath.Join(findingsDir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		filed, ok := parseFindingMarkdown(string(raw))
		if !ok {
			continue
		}
		loaded = append(loaded, diskFinding{
			seq:   n,
			entry: indexEntry(filed, path),
		})
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].seq < loaded[j].seq })

	index := make([]findingIndexEntry, 0, len(loaded))
	for _, item := range loaded {
		index = append(index, item.entry)
	}
	return index, max
}

func parseFindingMarkdown(raw string) (FindingFiled, bool) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "# ") {
		return FindingFiled{}, false
	}
	ep := findMarkdownField(lines, "- **Affected Endpoint**: ")
	if ep == "N/A" {
		ep = ""
	}
	filed := FindingFiled{
		Title:    strings.TrimSpace(strings.TrimPrefix(lines[0], "# ")),
		Severity: findMarkdownField(lines, "- **Severity**: "),
		Endpoint: ep,
	}
	filed.Description = findingSection(raw, "Description", "Reproduction Steps")
	filed.ReproductionSteps = findingSection(raw, "Reproduction Steps", "Evidence")
	filed.Evidence = findingSection(raw, "Evidence", "Impact")
	filed.Impact = findingSection(raw, "Impact", "Verification")
	filed.VerificationNotes = findingSection(raw, "Verification", "")
	if filed.Title == "" {
		return FindingFiled{}, false
	}
	return filed, true
}

func findMarkdownField(lines []string, prefix string) string {
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func findingSection(raw, heading, next string) string {
	marker := "## " + heading + "\n\n"
	start := strings.Index(raw, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	end := len(raw)
	if next != "" {
		nextMarker := "\n\n## " + next + "\n\n"
		if idx := strings.Index(raw[start:], nextMarker); idx >= 0 {
			end = start + idx
		}
	}
	return strings.TrimSpace(raw[start:end])
}

// IsDuplicate reports whether filed matches a written finding on exact title-slug AND canonical-endpoint equality.
func (w *FindingWriter) IsDuplicate(filed FindingFiled) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	titleSlug := util.Slugify(filed.Title)
	if titleSlug == "" {
		return false
	}
	canonEP := CanonicalEndpoint(filed.Endpoint)
	for _, e := range w.index {
		if titleSlug == e.titleSlug && canonEP == e.endpoint {
			return true
		}
	}
	return false
}

// MatchesFiled returns the title and path of a written finding whose title-slug AND canonical-endpoint
// match the inputs exactly, or ("", "", false) when none does.
func (w *FindingWriter) MatchesFiled(title, endpoint string) (matchedTitle, path string, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	titleSlug := util.Slugify(title)
	if titleSlug == "" {
		return "", "", false
	}
	canonEP := CanonicalEndpoint(endpoint)
	for _, e := range w.index {
		if titleSlug == e.titleSlug && canonEP == e.endpoint {
			return e.filed.Title, e.path, true
		}
	}
	return "", "", false
}

// FindSimilarEntries returns written findings whose title-slug matches or whose title is similar to filed.
func (w *FindingWriter) FindSimilarEntries(filed FindingFiled) []SimilarFinding {
	w.mu.Lock()
	defer w.mu.Unlock()

	titleSlug := util.Slugify(filed.Title)
	var out []SimilarFinding
	for _, e := range w.index {
		if titleSlug != "" && titleSlug == e.titleSlug {
			out = append(out, SimilarFinding{Filed: e.filed, Path: e.path})
			continue
		}
		if TitlesSimilar(filed.Title, e.filed.Title) {
			out = append(out, SimilarFinding{Filed: e.filed, Path: e.path})
		}
	}
	return out
}

// Write persists the finding to disk and updates the index.
func (w *FindingWriter) Write(filed FindingFiled) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(w.findingsDir, 0o755); err != nil {
		return "", err
	}
	nextCount := w.Count + 1
	path := filepath.Join(w.findingsDir, findingFilename(nextCount, filed.Title))
	if err := os.WriteFile(path, []byte(renderFinding(filed)), 0o644); err != nil {
		return "", err
	}
	w.Count = nextCount
	w.RunCount++
	w.Paths = append(w.Paths, path)
	w.index = append(w.index, indexEntry(filed, path))
	return path, nil
}

// Replace rewrites the finding at oldPath with filed, preserving the
// sequence number and renaming if the slug differs. Returns the new path.
func (w *FindingWriter) Replace(oldPath string, filed FindingFiled) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	idx := w.indexOfPath(oldPath)
	if idx < 0 {
		return "", fmt.Errorf("replace: path not tracked: %s", oldPath)
	}
	seq := findingSeqFromPath(oldPath)
	if seq <= 0 {
		return "", fmt.Errorf("replace: cannot parse sequence from %s", oldPath)
	}
	newPath := filepath.Join(w.findingsDir, findingFilename(seq, filed.Title))
	if err := os.WriteFile(newPath, []byte(renderFinding(filed)), 0o644); err != nil {
		return "", err
	}
	if newPath != oldPath {
		if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	w.index[idx] = indexEntry(filed, newPath)
	for i := range w.Paths {
		if w.Paths[i] == oldPath {
			w.Paths[i] = newPath
			break
		}
	}
	return newPath, nil
}

func (w *FindingWriter) indexOfPath(path string) int {
	for i, e := range w.index {
		if e.path == path {
			return i
		}
	}
	return -1
}

func findingFilename(seq int, title string) string {
	slug := util.Slugify(title)
	if slug == "" {
		slug = "untitled"
	}
	if len(slug) > 60 {
		slug = strings.TrimRight(slug[:60], "-")
	}
	return fmt.Sprintf("finding-%02d-%s.md", seq, slug)
}

func findingSeqFromPath(path string) int {
	m := findingIndexRe.FindStringSubmatch(filepath.Base(path))
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return n
}

func renderFinding(filed FindingFiled) string {
	endpoint := filed.Endpoint
	if endpoint == "" {
		endpoint = "N/A"
	}
	return fmt.Sprintf(
		`# %s

- **Severity**: %s
- **Affected Endpoint**: %s

## Description

%s

## Reproduction Steps

%s

## Evidence

%s

## Impact

%s

## Verification

%s
`,
		filed.Title,
		filed.Severity,
		endpoint,
		orDefault(filed.Description, noneSentinel),
		orDefault(filed.ReproductionSteps, noneSentinel),
		orDefault(filed.Evidence, noneSentinel),
		orDefault(filed.Impact, noneSentinel),
		orDefault(filed.VerificationNotes, noneSentinel),
	)
}

func indexEntry(filed FindingFiled, path string) findingIndexEntry {
	return findingIndexEntry{
		filed:     filed,
		titleSlug: util.Slugify(filed.Title),
		endpoint:  CanonicalEndpoint(filed.Endpoint),
		path:      path,
	}
}

// LookupByFilename returns the FindingFiled and full path for the finding
// whose file basename matches name, or (zero, "", false).
func (w *FindingWriter) LookupByFilename(name string) (FindingFiled, string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, e := range w.index {
		if filepath.Base(e.path) == name {
			return e.filed, e.path, true
		}
	}
	return FindingFiled{}, "", false
}

// FindingDigest is a compact summary of a filed finding for LLM dedup classification.
type FindingDigest struct {
	Filename   string
	Title      string
	Severity   string
	Endpoint   string
	FirstLines string // first lines of the description
}

// findingDigestDescriptionLines caps the description excerpt per digest.
const findingDigestDescriptionLines = 6

// Digests returns one FindingDigest per filed finding.
func (w *FindingWriter) Digests() []FindingDigest {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]FindingDigest, 0, len(w.index))
	for _, e := range w.index {
		lines := strings.SplitN(e.filed.Description, "\n", findingDigestDescriptionLines+1)
		if len(lines) > findingDigestDescriptionLines {
			lines = lines[:findingDigestDescriptionLines]
		}
		out = append(out, FindingDigest{
			Filename:   filepath.Base(e.path),
			Title:      e.filed.Title,
			Severity:   e.filed.Severity,
			Endpoint:   orDefault(e.filed.Endpoint, "N/A"),
			FirstLines: strings.Join(lines, "\n"),
		})
	}
	return out
}

// SummaryForOrchestrator renders a short listing of all filed findings.
func (w *FindingWriter) SummaryForOrchestrator() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.index) == 0 {
		return "No findings filed yet."
	}
	var sb strings.Builder
	sb.WriteString("**Findings filed so far:**\n")
	for i, e := range w.index {
		_, _ = fmt.Fprintf(&sb, "%d. [%s] %s — %s\n",
			i+1, orDefault(e.filed.Severity, "unknown"), e.filed.Title, orDefault(e.endpoint, "N/A"))
	}
	return strings.TrimRight(sb.String(), "\n")
}

// SummaryForWorker renders a compact title + endpoint listing for the worker prompt. Returns "" when no findings are filed.
func (w *FindingWriter) SummaryForWorker() string {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.index) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("**Findings filed so far — do not re-file:**\n")
	for _, e := range w.index {
		_, _ = fmt.Fprintf(&sb, "- %s — %s\n", e.filed.Title, orDefault(e.filed.Endpoint, "N/A"))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// unvalidatedTemplate renders an unvalidated candidate dumped at shutdown.
const unvalidatedTemplate = `# UNVALIDATED — %s

> ⚠ **THIS FINDING IS UNVALIDATED.** A worker reported it during the run, but
> the verifier never independently reproduced it because the operator
> interrupted the run before validation completed. The reported issue may be
> a false positive, already-known behavior, or unreachable in practice.
> **Do not rely on this as a confirmed finding.**

- **Severity (claimed)**: %s
- **Affected Endpoint (claimed)**: %s
- **Originating Worker**: %d
- **Candidate ID**: %s

## Worker Summary

%s

## Evidence Notes (worker-reported)

%s

## Reproduction Hint (worker-reported)

%s

## Flow IDs Touched

%s
`

// WriteUnvalidated persists c to disk as `unvalidated-NN-slug.md` and returns the path.
func (w *FindingWriter) WriteUnvalidated(c FindingCandidate) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := os.MkdirAll(w.findingsDir, 0o755); err != nil {
		return "", err
	}
	next := w.UnvalidatedCount + 1
	slug := util.Slugify(c.Title)
	if slug == "" {
		slug = "untitled"
	}
	if len(slug) > 60 {
		slug = strings.TrimRight(slug[:60], "-")
	}
	name := fmt.Sprintf("unvalidated-%02d-%s.md", next, slug)
	path := filepath.Join(w.findingsDir, name)
	flowList := noneSentinel
	if len(c.FlowIDs) > 0 {
		var fb strings.Builder
		for _, id := range c.FlowIDs {
			_, _ = fmt.Fprintf(&fb, "- %s\n", id)
		}
		flowList = strings.TrimRight(fb.String(), "\n")
	}
	body := fmt.Sprintf(unvalidatedTemplate,
		c.Title,
		orDefault(c.Severity, "unknown"),
		orDefault(c.Endpoint, "N/A"),
		c.WorkerID,
		c.CandidateID,
		orDefault(c.Summary, noneSentinel),
		orDefault(c.EvidenceNotes, noneSentinel),
		orDefault(c.ReproductionHint, noneSentinel),
		flowList,
	)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return "", err
	}
	w.UnvalidatedCount = next
	w.Paths = append(w.Paths, path)
	return path, nil
}

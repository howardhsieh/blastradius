package provider

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// maxFileSize caps how much of any file is read. Credential files are
// small; a huge file at one of these paths is not one we want in memory.
const maxFileSize = 4 << 20

// readFile reads path up to maxFileSize. ok is false when the file does not
// exist; a Problem is returned for any other error.
func readFile(path string) (data []byte, info fs.FileInfo, ok bool, prob *Problem) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, false, nil
		}
		return nil, nil, false, &Problem{Location: path, Err: errString(err)}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Follow symlinks for the content but keep the link's own path.
		info, err = os.Stat(path)
		if err != nil {
			return nil, nil, false, &Problem{Location: path, Err: errString(err)}
		}
	}
	if !info.Mode().IsRegular() {
		return nil, nil, false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, false, &Problem{Location: path, Err: errString(err)}
	}
	defer f.Close()
	data, err = io.ReadAll(io.LimitReader(f, maxFileSize))
	if err != nil {
		return nil, nil, false, &Problem{Location: path, Err: errString(err)}
	}
	return data, info, true, nil
}

// errString strips the path from an *os.PathError so problems do not repeat
// it, and never leak content.
func errString(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// ageDays returns whole days between the file's modification time and now.
func ageDays(env *Env, info fs.FileInfo) *int {
	if info == nil {
		return nil
	}
	d := env.Now.Sub(info.ModTime())
	if d < 0 {
		d = 0
	}
	return cred.Days(int(d / (24 * time.Hour)))
}

// unixPermsMeaningful reports whether a file's permission bits carry
// information on this OS. Windows reports 0666 for every file, so the Unix
// "group/other can read this" checks are meaningless and must be skipped there.
func unixPermsMeaningful() bool { return runtime.GOOS != "windows" }

// worldReadable reports whether others can read the file (Unix modes only).
func worldReadable(info fs.FileInfo) bool {
	return info != nil && unixPermsMeaningful() && info.Mode().Perm()&0o044 != 0
}

// section is one INI [section] with its key/value pairs in order.
type section struct {
	Name string
	Line int
	Keys []iniKey
}

type iniKey struct {
	Key, Value string
	Line       int
}

// Get returns the value of a key (case-insensitive) or "".
func (s *section) Get(key string) string {
	for _, k := range s.Keys {
		if strings.EqualFold(k.Key, key) {
			return k.Value
		}
	}
	return ""
}

// Has reports whether a key is present with a non-empty value.
func (s *section) Has(key string) bool { return s.Get(key) != "" }

// parseINI parses AWS/pypirc-style INI files. Keys before any section go
// into a section with an empty name.
func parseINI(data []byte) []section {
	var out []section
	cur := &section{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		t := strings.TrimSpace(sc.Text())
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		if t[0] == '[' && strings.HasSuffix(t, "]") {
			if cur.Name != "" || len(cur.Keys) > 0 {
				out = append(out, *cur)
			}
			cur = &section{Name: strings.TrimSpace(t[1 : len(t)-1]), Line: n}
			continue
		}
		// Nested keys (aws "s3 =\n  max_concurrent_requests = 10") are
		// indented; they are not credentials, keep them under their parent.
		sep := strings.IndexAny(t, "=:")
		if sep < 0 {
			continue
		}
		k := strings.TrimSpace(t[:sep])
		v := strings.TrimSpace(t[sep+1:])
		v = strings.Trim(v, `"'`)
		cur.Keys = append(cur.Keys, iniKey{Key: k, Value: v, Line: n})
	}
	if cur.Name != "" || len(cur.Keys) > 0 {
		out = append(out, *cur)
	}
	return out
}

// parseAssignment parses a shell/dotenv style "export KEY=value" line and
// returns the key and the unquoted value. ok is false for anything else.
func parseAssignment(line string) (key, value string, ok bool) {
	t := strings.TrimSpace(line)
	t = strings.TrimPrefix(t, "export ")
	t = strings.TrimPrefix(t, "set -gx ")
	t = strings.TrimPrefix(t, "set -x ")
	t = strings.TrimPrefix(t, "setenv ")
	t = strings.TrimSpace(t)
	if t == "" || t[0] == '#' {
		return "", "", false
	}
	eq := strings.IndexByte(t, '=')
	sp := strings.IndexByte(t, ' ')
	switch {
	case eq > 0 && (sp < 0 || eq < sp):
		key, value = t[:eq], t[eq+1:]
	case sp > 0 && strings.HasPrefix(line, "set ") || sp > 0 && strings.HasPrefix(strings.TrimSpace(line), "setenv "):
		// fish: set -gx KEY value ; csh: setenv KEY value
		key, value = t[:sp], t[sp+1:]
	default:
		return "", "", false
	}
	key = strings.TrimSpace(key)
	if !validVarName(key) {
		return "", "", false
	}
	return key, unquoteValue(value), true
}

func validVarName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// unquoteValue strips matching quotes and a trailing comment from a value.
func unquoteValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if v[0] == '"' || v[0] == '\'' {
		q := v[0]
		if end := strings.IndexByte(v[1:], q); end >= 0 {
			return v[1 : end+1]
		}
		return v[1:]
	}
	// Unquoted: stop at whitespace or " #".
	if i := strings.IndexAny(v, " \t"); i >= 0 {
		v = v[:i]
	}
	return v
}

// dynamicValue reports whether a value is computed at shell start
// ("$(op read ...)", "`...`", "$OTHER") rather than written in the file.
func dynamicValue(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "$") || strings.HasPrefix(v, "`") || strings.Contains(v, "$(")
}

// walkDirs visits regular files under each dir up to maxDepth, skipping the
// directories where secrets are never meant to live and that make a walk
// slow. fn returns false to stop early.
func walkDirs(dirs []string, maxDepth, maxFiles int, fn func(path string, d fs.DirEntry) bool) (truncated bool) {
	skip := map[string]bool{
		".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
		"__pycache__": true, ".cache": true, "dist": true, "build": true, ".next": true,
		".terraform": true, "target": true, ".gradle": true, "Library": true, ".Trash": true,
		"Pods": true, ".tox": true, ".mypy_cache": true, ".pytest_cache": true,
	}
	seen := 0
	for _, root := range dirs {
		root = filepath.Clean(root)
		base := strings.Count(root, string(filepath.Separator))
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path != root && (skip[d.Name()] || strings.Count(path, string(filepath.Separator))-base >= maxDepth) {
					return filepath.SkipDir
				}
				return nil
			}
			seen++
			if seen > maxFiles {
				truncated = true
				return filepath.SkipAll
			}
			if !fn(path, d) {
				return filepath.SkipAll
			}
			return nil
		})
		if err != nil {
			continue
		}
	}
	return truncated
}

// ageNote formats an age for a summary line.
func ageNote(age *int) string {
	if age == nil {
		return ""
	}
	switch {
	case *age == 0:
		return "modified today"
	case *age == 1:
		return "modified yesterday"
	case *age < 60:
		return fmt.Sprintf("modified %d days ago", *age)
	case *age < 730:
		return fmt.Sprintf("modified %d months ago", *age/30)
	default:
		return fmt.Sprintf("modified %d years ago", *age/365)
	}
}

// hostOf returns the host part of a URL or "host:port" string, for labels.
func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

// expiry parses an RFC 3339 timestamp and reports whether it has passed.
func expiry(env *Env, s string) (string, bool, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05UTC", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339), env.Now.After(t), true
		}
	}
	return "", false, false
}

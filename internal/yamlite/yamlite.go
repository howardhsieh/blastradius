// Package yamlite parses the small subset of YAML that tool configuration
// files use: block mappings, block sequences, plain/quoted scalars, literal
// and folded block scalars, comments and document markers. It exists so the
// tool can read ~/.config/gh/hosts.yml and kubeconfig files without a
// third-party dependency. Anchors, tags, flow collections and multi-document
// streams are out of scope; flow collections are returned as their raw text.
package yamlite

import (
	"fmt"
	"strings"
)

// Kind of a node.
type Kind int

const (
	Scalar Kind = iota
	Map
	Seq
)

// KV is one mapping entry, in document order.
type KV struct {
	Key  string
	Val  *Node
	Line int
}

// Node is a parsed YAML value.
type Node struct {
	Kind Kind
	Text string // Scalar
	Map  []KV   // Map
	Seq  []*Node
	Line int
}

// Get returns the value for key in a mapping, or nil.
func (n *Node) Get(key string) *Node {
	if n == nil || n.Kind != Map {
		return nil
	}
	for _, kv := range n.Map {
		if kv.Key == key {
			return kv.Val
		}
	}
	return nil
}

// String returns the scalar text, or "" for collections and nil.
func (n *Node) String() string {
	if n == nil || n.Kind != Scalar {
		return ""
	}
	return n.Text
}

// Str returns the scalar text of key in a mapping, or "".
func (n *Node) Str(key string) string { return n.Get(key).String() }

type line struct {
	num    int
	indent int
	text   string // content without indentation and trailing comment
	raw    string // content without indentation, comments kept (for block scalars)
	seqTab bool   // text started with "- " at this indent
}

type parser struct {
	lines []line
	pos   int
}

// Parse parses a YAML document.
func Parse(data []byte) (*Node, error) {
	p := &parser{}
	for i, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimLeft(raw, " ")
		if strings.HasPrefix(trimmed, "\t") {
			return nil, fmt.Errorf("line %d: tabs are not allowed for indentation", i+1)
		}
		p.lines = append(p.lines, line{num: i + 1, indent: len(raw) - len(trimmed), raw: trimmed, text: stripComment(trimmed)})
	}
	p.skipBlank()
	if p.pos >= len(p.lines) {
		return &Node{Kind: Map}, nil
	}
	n, err := p.parseBlock(p.lines[p.pos].indent)
	if err != nil {
		return nil, err
	}
	p.skipBlank()
	if p.pos < len(p.lines) {
		return nil, fmt.Errorf("line %d: unexpected content", p.lines[p.pos].num)
	}
	return n, nil
}

func (p *parser) skipBlank() {
	for p.pos < len(p.lines) {
		t := p.lines[p.pos].text
		if t == "" || t == "---" || t == "..." || strings.HasPrefix(t, "%") {
			p.pos++
			continue
		}
		break
	}
}

// parseBlock parses a mapping or sequence whose entries sit at indent.
func (p *parser) parseBlock(indent int) (*Node, error) {
	p.skipBlank()
	if p.pos >= len(p.lines) {
		return &Node{Kind: Scalar}, nil
	}
	l := p.lines[p.pos]
	if l.indent != indent {
		return nil, fmt.Errorf("line %d: bad indentation", l.num)
	}
	if strings.HasPrefix(l.text, "- ") || l.text == "-" {
		return p.parseSeq(indent)
	}
	if _, _, ok := splitKey(l.text); ok {
		return p.parseMap(indent)
	}
	// A lone scalar block.
	p.pos++
	return &Node{Kind: Scalar, Text: unquote(l.text), Line: l.num}, nil
}

func (p *parser) parseMap(indent int) (*Node, error) {
	n := &Node{Kind: Map, Line: p.lines[p.pos].num}
	for {
		p.skipBlank()
		if p.pos >= len(p.lines) {
			return n, nil
		}
		l := p.lines[p.pos]
		if l.indent < indent {
			return n, nil
		}
		if l.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", l.num)
		}
		if strings.HasPrefix(l.text, "- ") || l.text == "-" {
			return n, nil
		}
		key, rest, ok := splitKey(l.text)
		if !ok {
			return nil, fmt.Errorf("line %d: expected key: value", l.num)
		}
		p.pos++
		val, err := p.parseValue(rest, l, indent)
		if err != nil {
			return nil, err
		}
		n.Map = append(n.Map, KV{Key: key, Val: val, Line: l.num})
	}
}

func (p *parser) parseSeq(indent int) (*Node, error) {
	n := &Node{Kind: Seq, Line: p.lines[p.pos].num}
	for {
		p.skipBlank()
		if p.pos >= len(p.lines) {
			return n, nil
		}
		l := p.lines[p.pos]
		if l.indent < indent {
			return n, nil
		}
		if l.indent > indent || !(strings.HasPrefix(l.text, "- ") || l.text == "-") {
			return n, nil
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		p.pos++
		if rest == "" {
			val, err := p.parseNested(indent)
			if err != nil {
				return nil, err
			}
			n.Seq = append(n.Seq, val)
			continue
		}
		if key, kv, ok := splitKey(rest); ok {
			// "- key: value" starts an inline mapping whose further keys
			// are indented to the column after "- ".
			inner := indent + 2
			// Splice the first entry back in as a virtual line.
			first := line{num: l.num, indent: inner, text: rest, raw: strings.TrimSpace(strings.TrimPrefix(l.raw, "-"))}
			_ = key
			_ = kv
			p.lines = append(p.lines[:p.pos], append([]line{first}, p.lines[p.pos:]...)...)
			val, err := p.parseMap(inner)
			if err != nil {
				return nil, err
			}
			n.Seq = append(n.Seq, val)
			continue
		}
		val, err := p.parseValue(rest, l, indent)
		if err != nil {
			return nil, err
		}
		n.Seq = append(n.Seq, val)
	}
}

// parseValue handles what follows "key:" or "- ".
func (p *parser) parseValue(rest string, l line, indent int) (*Node, error) {
	switch {
	case rest == "":
		return p.parseNested(indent)
	case rest == "|" || rest == "|-" || rest == "|+" || rest == ">" || rest == ">-" || rest == ">+":
		return p.parseBlockScalar(rest, indent, l.num), nil
	default:
		return &Node{Kind: Scalar, Text: unquote(rest), Line: l.num}, nil
	}
}

// parseNested parses the block following a "key:" with no inline value.
func (p *parser) parseNested(indent int) (*Node, error) {
	p.skipBlank()
	if p.pos >= len(p.lines) {
		return &Node{Kind: Scalar}, nil
	}
	l := p.lines[p.pos]
	if l.indent > indent {
		return p.parseBlock(l.indent)
	}
	// A sequence may sit at the same indent as its parent key.
	if l.indent == indent && (strings.HasPrefix(l.text, "- ") || l.text == "-") {
		return p.parseSeq(indent)
	}
	return &Node{Kind: Scalar}, nil
}

func (p *parser) parseBlockScalar(indicator string, parentIndent, num int) *Node {
	var parts []string
	blockIndent := -1
	for p.pos < len(p.lines) {
		l := p.lines[p.pos]
		if l.raw == "" {
			parts = append(parts, "")
			p.pos++
			continue
		}
		if l.indent <= parentIndent {
			break
		}
		if blockIndent < 0 {
			blockIndent = l.indent
		}
		if l.indent < blockIndent {
			break
		}
		parts = append(parts, strings.Repeat(" ", l.indent-blockIndent)+l.raw)
		p.pos++
	}
	// Drop trailing blank lines (we always "clip").
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	sep := "\n"
	if strings.HasPrefix(indicator, ">") {
		sep = " "
	}
	return &Node{Kind: Scalar, Text: strings.Join(parts, sep), Line: num}
}

// splitKey splits "key: value" / "key:" into key and the rest.
func splitKey(text string) (key, rest string, ok bool) {
	if text == "" || text[0] == '[' || text[0] == '{' {
		return "", "", false
	}
	if text[0] == '"' || text[0] == '\'' {
		q := text[0]
		end := strings.IndexByte(text[1:], q)
		if end < 0 {
			return "", "", false
		}
		key = text[1 : end+1]
		after := text[end+2:]
		if !strings.HasPrefix(after, ":") {
			return "", "", false
		}
		after = after[1:]
		if after != "" && after[0] != ' ' {
			return "", "", false
		}
		return key, strings.TrimSpace(after), true
	}
	for i := 0; i < len(text); i++ {
		if text[i] == ':' && (i+1 == len(text) || text[i+1] == ' ') {
			return strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:]), true
		}
	}
	return "", "", false
}

// stripComment removes a trailing " # comment" outside quotes.
func stripComment(s string) string {
	if strings.HasPrefix(s, "#") {
		return ""
	}
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS && (i == 0 || s[i-1] != '\\') {
				inD = !inD
			}
		case '#':
			if !inS && !inD && i > 0 && s[i-1] == ' ' {
				return strings.TrimRight(s[:i], " ")
			}
		}
	}
	return strings.TrimRight(s, " ")
}

func unquote(s string) string {
	if len(s) >= 2 {
		switch {
		case s[0] == '"' && s[len(s)-1] == '"':
			var b strings.Builder
			inner := s[1 : len(s)-1]
			for i := 0; i < len(inner); i++ {
				if inner[i] == '\\' && i+1 < len(inner) {
					i++
					switch inner[i] {
					case 'n':
						b.WriteByte('\n')
					case 't':
						b.WriteByte('\t')
					default:
						b.WriteByte(inner[i])
					}
					continue
				}
				b.WriteByte(inner[i])
			}
			return b.String()
		case s[0] == '\'' && s[len(s)-1] == '\'':
			return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
		}
	}
	return s
}

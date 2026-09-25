package main

// Web UI saves keep router.yaml as written: comments, key order, quoting, blank lines and alignment
// stay; only the values the page changed are edited in the text (Cd1s/mini-router#11).
//
// The page submits the whole config. Both the live file and the submission are decoded into Config
// and encoded canonically (struct order, omitempty); the two canonical trees are compared, and the
// live file's text is edited where they differ — a scalar in place, map entries added (after the
// last one) or removed, lists matched by `name` (or by position), a flow collection rewritten on its
// line. Everything else is copied byte for byte. The result must decode to exactly the submitted
// config, else the canonical encoding is written (comments lost) and the reason logged.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

var errLayout = errors.New("cannot edit this in place")

// uiConfigYAML is the router.yaml to install for the web UI's config: y is the page's config as YAML
// (configFromJSON), c the same config with defaults and secrets (what was validated and planned).
func uiConfigYAML(y []byte, c *Config) []byte {
	cur, err := os.ReadFile(ConfigPath)
	if err == nil {
		out, err := keepLayout(cur, y, c)
		if err == nil {
			return out
		}
		logf("web UI save: router.yaml rewritten in canonical form (comments not kept): %v", err)
	}
	want, err := decodeConfig(y)
	if err != nil {
		return append([]byte("# written by the web UI\n"), y...)
	}
	b, _ := yaml.Marshal(want)
	return append([]byte("# written by the web UI\n"), b...)
}

// keepLayout edits cur (the live router.yaml) into a file that decodes to c.
func keepLayout(cur, y []byte, c *Config) ([]byte, error) {
	base, err := decodeConfig(cur)
	if err != nil {
		return nil, err
	}
	base.secrets = c.secrets
	base.defaults()
	want, err := decodeConfig(y)
	if err != nil {
		return nil, err
	}
	bn, err := canonNode(base)
	if err != nil {
		return nil, err
	}
	wn, err := canonNode(want)
	if err != nil {
		return nil, err
	}
	out, err := mergeYAML(cur, bn, wn)
	if err != nil {
		return nil, err
	}
	cn, err := canonNode(c)
	if err != nil {
		return nil, err
	}
	w, _ := yaml.Marshal(c)
	for pass := 0; ; pass++ {
		got, err := decodeConfig(out)
		if err != nil {
			return nil, fmt.Errorf("edited file does not load: %w", err)
		}
		got.secrets = c.secrets
		got.defaults()
		if g, _ := yaml.Marshal(got); bytes.Equal(g, w) {
			return out, nil
		}
		if pass == 2 {
			return nil, errors.New("edited file would not match the submitted config")
		}
		// the page sent values that defaults derive from other settings (a pool's lease, RA
		// details); with those settings changed the file must spell them out as the page had them
		gn, err := canonNode(got)
		if err != nil {
			return nil, err
		}
		if out, err = mergeYAML(out, gn, cn); err != nil {
			return nil, err
		}
	}
}

func decodeConfig(y []byte) (*Config, error) {
	c := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(y))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, err
	}
	c.secrets = map[string]string{}
	return c, nil
}

// canonNode: the mapping node of c's canonical encoding.
func canonNode(c *Config) (*yaml.Node, error) {
	b, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	var d yaml.Node
	if err := yaml.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return d.Content[0], nil
}

// mergeYAML edits src so that its values become want's wherever base and want differ.
func mergeYAML(src []byte, base, want *yaml.Node) ([]byte, error) {
	var d, more yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(src))
	if err := dec.Decode(&d); err != nil {
		return nil, err
	}
	if err := dec.Decode(&more); err != io.EOF {
		return nil, errors.New("router.yaml holds more than one document")
	}
	if d.Kind != yaml.DocumentNode || len(d.Content) != 1 || d.Content[0].Kind != yaml.MappingNode || hasAlias(&d) {
		return nil, errors.New("router.yaml is not a single plain mapping")
	}
	t := newYtext(src)
	root := d.Content[0]
	if len(root.Content) == 0 {
		return nil, errLayout
	}
	a := t.nodeStart(root)
	body, err := t.mapping(root, base, want, a, len(src))
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, src[:a]...), body...), nil
}

func hasAlias(n *yaml.Node) bool {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return true
	}
	for _, c := range n.Content {
		if hasAlias(c) {
			return true
		}
	}
	return false
}

// ---- the text ----

type ytext struct {
	src   []byte
	lines []int // offset of each line's first byte
}

func newYtext(src []byte) *ytext {
	t := &ytext{src: src, lines: []int{0}}
	for i, b := range src {
		if b == '\n' {
			t.lines = append(t.lines, i+1)
		}
	}
	return t
}

// off: the byte offset of a node position (1-based line, 1-based column counted in characters).
func (t *ytext) off(line, col int) int {
	o := t.lines[line-1]
	for c := 1; c < col && o < len(t.src) && t.src[o] != '\n'; c++ {
		_, n := utf8.DecodeRune(t.src[o:])
		o += n
	}
	return o
}

func (t *ytext) at(n *yaml.Node) int { return t.off(n.Line, n.Column) }

func (t *ytext) lineStart(o int) int {
	for o > 0 && t.src[o-1] != '\n' {
		o--
	}
	return o
}

// lineEnd: the offset after o's line (after its '\n').
func (t *ytext) lineEnd(o int) int {
	if i := bytes.IndexByte(t.src[o:], '\n'); i >= 0 {
		return o + i + 1
	}
	return len(t.src)
}

func (t *ytext) firstOnLine(o int) bool {
	return len(bytes.Trim(t.src[t.lineStart(o):o], " ")) == 0
}

// nodeStart: where a node's text begins. A block collection that starts its line owns the whole line
// (its indentation too), so its entries are whole lines.
func (t *ytext) nodeStart(n *yaml.Node) int {
	o := t.at(n)
	if (n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode) && n.Style&yaml.FlowStyle == 0 && t.firstOnLine(o) {
		return t.lineStart(o)
	}
	return o
}

// withHead: the start of the line holding o (a key or a dash that starts its line), moved up over
// the comment lines directly above it at the same indentation — they belong to that entry.
func (t *ytext) withHead(o int) int {
	s := t.lineStart(o)
	ind := o - s
	for s > 0 {
		ps := t.lineStart(s - 1)
		line := t.src[ps : s-1]
		tr := bytes.TrimLeft(line, " ")
		if len(tr) == 0 || tr[0] != '#' || len(line)-len(tr) != ind {
			break
		}
		s = ps
	}
	return s
}

// contentEnd: the end of the last line in [a, b) that holds content: not blank, and not a comment
// at the collection's indentation (ind) or less — those trail the collection.
func (t *ytext) contentEnd(a, b, ind int) int {
	end := a
	for s := a; s < b; {
		e := t.lineEnd(s)
		if e > b {
			e = b
		}
		line := bytes.TrimRight(t.src[s:e], " \r\n")
		tr := bytes.TrimLeft(line, " ")
		lind := len(line) - len(tr)
		if s == a {
			lind = ind + 1 // a may be mid-line (after "- "): that line is always content
		}
		if len(tr) > 0 && !(tr[0] == '#' && lind <= ind) {
			end = e
		}
		s = e
	}
	return end
}

// scalarEnd: the end of the scalar token starting at a.
func (t *ytext) scalarEnd(a int, style yaml.Style, flow bool) (int, error) {
	s := t.src
	switch {
	case style&yaml.DoubleQuotedStyle != 0:
		for i := a + 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++
			case '"':
				return i + 1, nil
			case '\n':
				return 0, errLayout
			}
		}
	case style&yaml.SingleQuotedStyle != 0:
		for i := a + 1; i < len(s); i++ {
			switch s[i] {
			case '\'':
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				return i + 1, nil
			case '\n':
				return 0, errLayout
			}
		}
	case style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		return 0, errLayout
	default:
		i := a
		for ; i < len(s) && s[i] != '\n'; i++ {
			if s[i] == '#' && i > a && (s[i-1] == ' ' || s[i-1] == '\t') {
				break
			}
			if flow && (s[i] == ',' || s[i] == ']' || s[i] == '}') {
				break
			}
		}
		for i > a && (s[i-1] == ' ' || s[i-1] == '\t' || s[i-1] == '\r') {
			i--
		}
		return i, nil
	}
	return 0, errLayout
}

// flowEnd: the end of the flow collection whose '[' or '{' is at a.
func (t *ytext) flowEnd(a int) (int, error) {
	depth := 0
	for i := a; i < len(t.src); i++ {
		switch t.src[i] {
		case '"':
			e, err := t.scalarEnd(i, yaml.DoubleQuotedStyle, true)
			if err != nil {
				return 0, err
			}
			i = e - 1
		case '\'':
			e, err := t.scalarEnd(i, yaml.SingleQuotedStyle, true)
			if err != nil {
				return 0, err
			}
			i = e - 1
		case '[', '{':
			depth++
		case ']', '}':
			depth--
			if depth == 0 {
				return i + 1, nil
			}
		case '#':
			return 0, errLayout // a comment inside a flow collection
		}
	}
	return 0, errLayout
}

// ---- merging ----

// value returns the new text for src[a:b], which holds node o (the value of a map entry or a list
// item) and whatever trails it up to the next entry. ind is the indentation of the entry that owns
// it; flow: o sits inside a flow collection.
func (t *ytext) value(o, base, want *yaml.Node, a, b, ind int, flow bool) (string, error) {
	src := t.src
	if base != nil && nodeEqual(base, want) {
		return string(src[a:b]), nil
	}
	oflow := o.Style&yaml.FlowStyle != 0
	switch {
	case o.Kind == yaml.ScalarNode && o.ShortTag() == "!!null" && o.Value == "":
		// `key:` with nothing after it
		if want.Kind == yaml.ScalarNode || isInline(want) {
			return " " + renderFlow(want) + string(src[a:b]), nil
		}
		return "\n" + renderBlockValue(want, ind+2) + string(src[t.lineEnd(a):b]), nil
	case o.Kind == yaml.ScalarNode && want.Kind == yaml.ScalarNode:
		if strings.Contains(want.Value, "\n") {
			return "", errLayout
		}
		e, err := t.scalarEnd(a, o.Style, flow)
		if err != nil {
			return "", err
		}
		if o.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) == 0 && string(src[a:e]) != o.Value {
			return "", errLayout // a plain scalar over several lines
		}
		return encScalar(want, o.Style, flow) + string(src[e:b]), nil
	case o.Kind != want.Kind || o.Kind == yaml.ScalarNode:
		return "", errLayout
	case oflow:
		e, err := t.flowEnd(a)
		if err != nil {
			return "", err
		}
		if !flow && len(o.Content) == 0 && !isInline(want) {
			// `forwards: []` gets its first item, `x: {}` its first key: block form on the next lines
			return "\n" + renderBlockValue(want, ind+2) + string(src[t.lineEnd(e):b]), nil
		}
		if s, err := t.flowEdit(o, base, want, a, e); err == nil {
			return s + string(src[e:b]), nil
		}
		return renderFlow(spelled(o, base, want)) + string(src[e:b]), nil
	case o.Kind == yaml.MappingNode:
		return t.mapping(o, base, want, a, b)
	default:
		return t.sequence(o, base, want, a, b)
	}
}

// flowEdit edits a flow collection [a, e) in place: changed values are replaced where they stand,
// removed keys cut out with their comma, new keys added before the closing brace — the rest of the
// text (line breaks, alignment) stays. Lists must keep their length.
func (t *ytext) flowEdit(o, base, want *yaml.Node, a, e int) (string, error) {
	src := t.src
	type edit struct {
		s, e int
		text string
	}
	var edits []edit
	// change replaces value v (whose base is bv) by wv
	change := func(v, bv, wv *yaml.Node) error {
		if bv != nil && nodeEqual(bv, wv) {
			return nil
		}
		s := t.at(v)
		switch {
		case v.Kind == yaml.ScalarNode && wv.Kind == yaml.ScalarNode && !(v.ShortTag() == "!!null" && v.Value == ""):
			end, err := t.scalarEnd(s, v.Style, true)
			if err != nil {
				return err
			}
			if v.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) == 0 && string(src[s:end]) != v.Value {
				return errLayout
			}
			edits = append(edits, edit{s, end, encScalar(wv, v.Style, true)})
		case v.Style&yaml.FlowStyle != 0 && v.Kind == wv.Kind:
			end, err := t.flowEnd(s)
			if err != nil {
				return err
			}
			text, err := t.flowEdit(v, bv, wv, s, end)
			if err != nil {
				text = renderFlow(spelled(v, bv, wv))
			}
			edits = append(edits, edit{s, end, text})
		default:
			return errLayout
		}
		return nil
	}
	switch {
	case o.Kind == yaml.SequenceNode && want.Kind == yaml.SequenceNode && len(o.Content) == len(want.Content):
		for i, v := range o.Content {
			var bv *yaml.Node
			if base != nil && len(base.Content) == len(o.Content) {
				bv = base.Content[i]
			}
			if err := change(v, bv, want.Content[i]); err != nil {
				return "", err
			}
		}
	case o.Kind == yaml.MappingNode && want.Kind == yaml.MappingNode:
		om, wm, bm := mapIndex(o), mapIndex(want), mapIndex(base)
		last := a + 1 // where new keys go: after the last value
		for i := 0; i+1 < len(o.Content); i += 2 {
			k, v := o.Content[i], o.Content[i+1]
			ve, err := t.valueEnd(v)
			if err != nil {
				return "", err
			}
			last = ve
			wv, ok := wm[k.Value]
			switch {
			case ok:
				if err := change(v, bm[k.Value], wv); err != nil {
					return "", err
				}
			case bm[k.Value] == nil: // in neither canonical form: a zero value spelled out
			default: // removed: "k: v, " or ", k: v" on the same line
				ks := t.at(k)
				n := ve
				for n < e && src[n] == ' ' {
					n++
				}
				if n < e && src[n] == ',' && n+1 < e && src[n+1] != '\n' && src[n+1] != '\r' {
					n++
					for n < e && src[n] == ' ' {
						n++
					}
					edits = append(edits, edit{ks, n, ""})
					break
				}
				p := ks
				for p > a && src[p-1] == ' ' {
					p--
				}
				if p <= a || src[p-1] != ',' {
					return "", errLayout
				}
				edits = append(edits, edit{p - 1, ve, ""})
			}
		}
		var add strings.Builder
		for i := 0; i+1 < len(want.Content); i += 2 {
			k, wv := want.Content[i], want.Content[i+1]
			if om[k.Value] != nil {
				continue
			}
			if bv := bm[k.Value]; bv != nil && nodeEqual(bv, wv) {
				continue // a default the page left alone
			}
			if len(o.Content) > 0 || add.Len() > 0 {
				add.WriteString(", ")
			}
			add.WriteString(encScalar(k, 0, true) + ": " + renderFlow(delta(bm[k.Value], wv)))
		}
		if add.Len() > 0 {
			edits = append(edits, edit{last, last, add.String()})
		}
	default:
		return "", errLayout
	}
	sortEdits := func() {
		for i := 1; i < len(edits); i++ {
			for j := i; j > 0 && edits[j].s < edits[j-1].s; j-- {
				edits[j], edits[j-1] = edits[j-1], edits[j]
			}
		}
	}
	sortEdits()
	var out strings.Builder
	p := a
	for _, ed := range edits {
		if ed.s < p {
			return "", errLayout
		}
		out.Write(src[p:ed.s])
		out.WriteString(ed.text)
		p = ed.e
	}
	out.Write(src[p:e])
	return out.String(), nil
}

// valueEnd: the end of a value inside a flow collection.
func (t *ytext) valueEnd(v *yaml.Node) (int, error) {
	s := t.at(v)
	if v.Kind == yaml.ScalarNode {
		if v.ShortTag() == "!!null" && v.Value == "" {
			return s, nil
		}
		return t.scalarEnd(s, v.Style, true)
	}
	return t.flowEnd(s)
}

// mapping merges a block mapping; [a, b) is its region (a: its first key, or that key's line).
func (t *ytext) mapping(o, base, want *yaml.Node, a, b int) (string, error) {
	src := t.src
	n := len(o.Content) / 2
	ind := o.Content[0].Column - 1
	starts := make([]int, n+1)
	starts[0], starts[n] = a, b
	for i := 1; i < n; i++ {
		starts[i] = t.withHead(t.at(o.Content[2*i]))
	}
	ce := t.contentEnd(starts[n-1], b, ind)
	bm, wm := mapIndex(base), mapIndex(want)
	seen := map[string]bool{}
	var out []string
	for i := 0; i < n; i++ {
		k, v := o.Content[2*i], o.Content[2*i+1]
		seen[k.Value] = true
		end := starts[i+1]
		if i == n-1 {
			end = ce
		}
		wv, inWant := wm[k.Value]
		bv, inBase := bm[k.Value]
		switch {
		case !inWant && !inBase: // not in either canonical form (a zero value spelled out): unchanged
			out = append(out, string(src[starts[i]:end]))
		case !inWant: // removed; blank lines after it still separate what surrounds it
			if tr := string(src[t.contentEnd(starts[i], end, ind):end]); i < n-1 && tr != "" &&
				strings.TrimSpace(tr) == "" && (len(out) == 0 || !strings.HasSuffix(out[len(out)-1], "\n\n")) {
				out = append(out, tr)
			}
		case inBase && nodeEqual(bv, wv):
			out = append(out, string(src[starts[i]:end]))
		case isEmptyColl(wv) && (v.Kind == yaml.MappingNode || v.Kind == yaml.SequenceNode) && v.Style&yaml.FlowStyle == 0:
			// the last list item / key went: `key: []` instead of a bare `key:`
			head := t.lineStart(t.at(k))
			if head < starts[i] {
				head = starts[i]
			}
			out = append(out, string(src[starts[i]:head])+renderEntry(encKey(k), wv, ind))
		default:
			vs := t.nodeStart(v)
			s, err := t.value(v, bv, wv, vs, end, ind, false)
			if err != nil {
				return "", err
			}
			out = append(out, string(src[starts[i]:vs])+s)
		}
	}
	// keys only in want: new, or a default the file never spelled out that now changes
	for j := 0; j < len(want.Content); j += 2 {
		k, wv := want.Content[j], want.Content[j+1]
		if seen[k.Value] {
			continue
		}
		if bv, ok := bm[k.Value]; ok && nodeEqual(bv, wv) {
			continue
		}
		e := renderEntry(encKey(k), delta(bm[k.Value], wv), ind)
		if ind == 0 {
			e = "\n" + e // top-level sections are separated by a blank line
		}
		out = append(out, e)
	}
	if len(out) > 0 && a != t.lineStart(a) {
		out[0] = strings.TrimLeft(out[0], " ") // a starts mid-line ("- key: ..."): no indentation there
	}
	return joinLines(out) + string(src[ce:b]), nil
}

// sequence merges a block sequence; [a, b) is its region (a: the first dash's line).
func (t *ytext) sequence(o, base, want *yaml.Node, a, b int) (string, error) {
	src := t.src
	n := len(o.Content)
	if n == 0 {
		return "", errLayout
	}
	dashes := make([]int, n)
	for j, it := range o.Content {
		d := t.at(it) - 1
		for d > 0 && (src[d] == ' ' || src[d] == '\n' || src[d] == '\r') {
			d--
		}
		if src[d] != '-' {
			return "", errLayout
		}
		dashes[j] = d
	}
	ind := dashes[0] - t.lineStart(dashes[0])
	starts := make([]int, n+1)
	starts[0], starts[n] = a, b
	for j := 1; j < n; j++ {
		starts[j] = t.withHead(dashes[j])
	}
	ce := t.contentEnd(starts[n-1], b, ind)
	flowItems := o.Content[0].Kind == yaml.MappingNode && o.Content[0].Style&yaml.FlowStyle != 0
	item := func(j int, bi, wi *yaml.Node) (string, error) {
		end := starts[j+1]
		if j == n-1 {
			end = ce
		}
		if bi != nil && nodeEqual(bi, wi) {
			return string(src[starts[j]:end]), nil
		}
		it := o.Content[j]
		vs := t.nodeStart(it)
		if vs < dashes[j] {
			vs = t.at(it)
		}
		s, err := t.value(it, bi, wi, vs, end, ind+2, false)
		if err != nil {
			return "", err
		}
		return string(src[starts[j]:vs]) + s, nil
	}
	var out []string
	switch {
	case named(o) && named(want) && (base == nil || named(base)):
		oi, bi := nameIndex(o), nameIndex(base)
		for _, wi := range want.Content {
			nm := itemName(wi)
			j, ok := oi[nm]
			if !ok {
				out = append(out, renderItem(wi, ind, flowItems))
				continue
			}
			var bn *yaml.Node
			if k, ok := bi[nm]; ok {
				bn = base.Content[k]
			}
			s, err := item(j, bn, wi)
			if err != nil {
				return "", err
			}
			out = append(out, s)
		}
	case len(want.Content) == n:
		for j := 0; j < n; j++ {
			var bn *yaml.Node
			if base != nil && len(base.Content) == n {
				bn = base.Content[j]
			}
			s, err := item(j, bn, want.Content[j])
			if err != nil {
				return "", err
			}
			out = append(out, s)
		}
	default: // unnamed items added or removed: the list is written anew
		for _, wi := range want.Content {
			out = append(out, renderItem(wi, ind, flowItems))
		}
	}
	return joinLines(out) + string(src[ce:b]), nil
}

// joinLines concatenates entry texts, each on its own line(s).
func joinLines(parts []string) string {
	var b strings.Builder
	for i, p := range parts {
		b.WriteString(p)
		if i < len(parts)-1 && !strings.HasSuffix(p, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// ---- canonical trees ----

func nodeEqual(a, b *yaml.Node) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Kind != b.Kind || a.ShortTag() != b.ShortTag() || len(a.Content) != len(b.Content) {
		return false
	}
	if a.Kind == yaml.ScalarNode && a.Value != b.Value {
		return false
	}
	for i := range a.Content {
		if !nodeEqual(a.Content[i], b.Content[i]) {
			return false
		}
	}
	return true
}

func mapIndex(n *yaml.Node) map[string]*yaml.Node {
	m := map[string]*yaml.Node{}
	if n != nil && n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = n.Content[i+1]
		}
	}
	return m
}

func itemName(n *yaml.Node) string {
	if v := mapIndex(n)["name"]; v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

// named: a list of mappings with unique, non-empty names.
func named(n *yaml.Node) bool {
	if n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		return n.Kind == yaml.SequenceNode
	}
	seen := map[string]bool{}
	for _, it := range n.Content {
		nm := itemName(it)
		if nm == "" || seen[nm] {
			return false
		}
		seen[nm] = true
	}
	return true
}

func nameIndex(n *yaml.Node) map[string]int {
	m := map[string]int{}
	if n != nil {
		for j, it := range n.Content {
			m[itemName(it)] = j
		}
	}
	return m
}

// spelled: want without the keys o never had whose value is still base's (defaults the page sent back).
func spelled(o, base, want *yaml.Node) *yaml.Node {
	if want.Kind != yaml.MappingNode || o.Kind != yaml.MappingNode {
		return want
	}
	om, bm := mapIndex(o), mapIndex(base)
	c := *want
	c.Content = nil
	for i := 0; i+1 < len(want.Content); i += 2 {
		k, v := want.Content[i], want.Content[i+1]
		if bv := bm[k.Value]; om[k.Value] == nil && bv != nil && nodeEqual(bv, v) {
			continue
		}
		c.Content = append(c.Content, k, v)
	}
	return &c
}

// delta: the keys of mapping want whose values differ from base's (all of want when base is not a
// mapping) — a value the file never had needs only what differs from what it gets without them.
func delta(base, want *yaml.Node) *yaml.Node {
	if base == nil || base.Kind != yaml.MappingNode || want.Kind != yaml.MappingNode {
		return want
	}
	bm := mapIndex(base)
	c := *want
	c.Content = nil
	for i := 0; i+1 < len(want.Content); i += 2 {
		if bv := bm[want.Content[i].Value]; bv == nil || !nodeEqual(bv, want.Content[i+1]) {
			c.Content = append(c.Content, want.Content[i], want.Content[i+1])
		}
	}
	return &c
}

func isEmptyColl(n *yaml.Node) bool {
	return (n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode) && len(n.Content) == 0
}

// isInline: written on one line — scalars, and lists of scalars ([a, b]), empty collections.
func isInline(n *yaml.Node) bool {
	switch n.Kind {
	case yaml.ScalarNode:
		return true
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c.Kind != yaml.ScalarNode {
				return false
			}
		}
		return true
	}
	return len(n.Content) == 0
}

// ---- rendering new text ----

func dquote(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

// encScalar writes want's value; strings keep the quoting of the value they replace (orig).
func encScalar(want *yaml.Node, orig yaml.Style, flow bool) string {
	v := want.Value
	if want.ShortTag() != "!!str" {
		return v
	}
	switch {
	case orig&yaml.DoubleQuotedStyle != 0:
		return dquote(v)
	case orig&yaml.SingleQuotedStyle != 0:
		return "'" + strings.ReplaceAll(v, "'", "''") + "'"
	case want.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0 || !plainSafe(v, flow):
		return dquote(v)
	}
	return v
}

// plainSafe: v can be written unquoted (conservative: anything that could read as syntax is quoted).
func plainSafe(v string, flow bool) bool {
	if v == "" || v != strings.TrimSpace(v) || strings.ContainsAny(v, "\t\r\n") ||
		strings.Contains(v, ": ") || strings.Contains(v, " #") || strings.HasSuffix(v, ":") ||
		strings.ContainsRune("-?:,[]{}#&*!|>'\"%@`", rune(v[0])) {
		return false
	}
	return !flow || !strings.ContainsAny(v, ",[]{}")
}

func encKey(k *yaml.Node) string { return encScalar(k, 0, false) }

// renderFlow writes n on one line: [a, b], {k: v}.
func renderFlow(n *yaml.Node) string {
	switch n.Kind {
	case yaml.SequenceNode:
		parts := make([]string, len(n.Content))
		for i, c := range n.Content {
			parts[i] = renderFlow(c)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case yaml.MappingNode:
		var parts []string
		for i := 0; i+1 < len(n.Content); i += 2 {
			parts = append(parts, encScalar(n.Content[i], 0, true)+": "+renderFlow(n.Content[i+1]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return encScalar(n, 0, true)
}

// renderEntry writes `key: value` at indentation ind; nested mappings and lists of mappings as blocks,
// scalar lists inline.
func renderEntry(key string, v *yaml.Node, ind int) string {
	pad := strings.Repeat(" ", ind)
	if isInline(v) {
		return pad + key + ": " + renderFlow(v) + "\n"
	}
	return pad + key + ":\n" + renderBlockValue(v, ind+2)
}

// renderBlockValue writes a mapping's entries or a list's items at indentation ind.
func renderBlockValue(v *yaml.Node, ind int) string {
	var b strings.Builder
	if v.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(v.Content); i += 2 {
			b.WriteString(renderEntry(encKey(v.Content[i]), v.Content[i+1], ind))
		}
		return b.String()
	}
	for _, it := range v.Content {
		b.WriteString(renderItem(it, ind, false))
	}
	return b.String()
}

// renderItem writes a list item at indentation ind (the dash's); flow: mappings as {k: v} like
// their siblings.
func renderItem(v *yaml.Node, ind int, flow bool) string {
	pad := strings.Repeat(" ", ind)
	if v.Kind != yaml.MappingNode || flow || len(v.Content) == 0 {
		if isInline(v) || flow || v.Kind == yaml.MappingNode {
			return pad + "- " + renderFlow(v) + "\n"
		}
		return pad + "-\n" + renderBlockValue(v, ind+2)
	}
	s := renderBlockValue(v, ind+2)
	return pad + "- " + s[ind+2:]
}

package main

// Config paths (Cd1s/mini-router#17): one syntax for `mr get / set / add / del / export` and the
// API's patches. A path walks the config the way router.yaml spells it:
//
//	firewall.forwards[nas-ssh].enabled       list items by name (phy, ssid or mac in lists without names)
//	dhcp.hosts[mac=aa:bb:cc:dd:ee:ff].ip     by any key of the items
//	system.ntp[pool.ntp.org], system.ntp[0]  lists of values: by value, else by position
//	system.sysctl."net.core.rmem_max"        keys (and names) with dots or brackets in double quotes
//
// Reads see the effective config (router.yaml with defaults). Edits change the config as written
// (without defaults, so values derived from others follow them) and are made in the text of
// router.yaml like the web UI's saves (mergeYAML): comments, order and layout stay, only the edited
// values change. `del` puts a value back to its default. Secrets are never here: router.yaml only
// names them.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type pathStep struct {
	key  string // a mapping key (sel false)
	sel  bool   // a list item: [val] or [selK=val]
	selK string
	val  string
}

func identChar(b byte) bool {
	return b == '_' || b == '-' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// parsePath splits a path into its steps.
func parsePath(p string) ([]pathStep, error) {
	var out []pathStep
	i := 0
	quoted := func() (string, error) {
		q, err := strconv.QuotedPrefix(p[i:])
		if err != nil {
			return "", fmt.Errorf("bad quoted string at %d", i+1)
		}
		i += len(q)
		return strconv.Unquote(q)
	}
	for i < len(p) {
		if len(out) > 0 && p[i] == '[' {
			i++
			st := pathStep{sel: true}
			j := i
			for j < len(p) && identChar(p[j]) {
				j++
			}
			if j > i && j < len(p) && p[j] == '=' {
				st.selK, i = p[i:j], j+1
			}
			if i < len(p) && p[i] == '"' {
				v, err := quoted()
				if err != nil {
					return nil, err
				}
				st.val = v
			} else {
				e := strings.IndexByte(p[i:], ']')
				if e < 0 {
					return nil, errors.New("missing ]")
				}
				st.val, i = p[i:i+e], i+e
				if st.val == "" {
					return nil, fmt.Errorf("empty [] at %d", i)
				}
			}
			if i >= len(p) || p[i] != ']' {
				return nil, fmt.Errorf("missing ] at %d", i+1)
			}
			i++
			out = append(out, st)
			continue
		}
		if len(out) > 0 {
			if p[i] != '.' {
				return nil, fmt.Errorf("expected . or [ at %d", i+1)
			}
			i++
		}
		if i < len(p) && p[i] == '"' {
			k, err := quoted()
			if err != nil {
				return nil, err
			}
			out = append(out, pathStep{key: k})
			continue
		}
		j := i
		for j < len(p) && !strings.ContainsRune(".[]\"= \t", rune(p[j])) {
			j++
		}
		if j == i {
			return nil, fmt.Errorf("empty key at %d", i+1)
		}
		out = append(out, pathStep{key: p[i:j]})
		i = j
	}
	if len(out) == 0 {
		return nil, errors.New("empty path")
	}
	return out, nil
}

// fmtPath writes steps back in the syntax parsePath reads.
func fmtPath(steps []pathStep) string {
	var b strings.Builder
	for i, st := range steps {
		if st.sel {
			b.WriteString("[")
			if st.selK != "" {
				b.WriteString(st.selK + "=")
			}
			b.WriteString(fmtSel(st.val))
			b.WriteString("]")
			continue
		}
		if i > 0 {
			b.WriteString(".")
		}
		b.WriteString(fmtKey(st.key))
	}
	return b.String()
}

func fmtKey(k string) string {
	for i := 0; i < len(k); i++ {
		if !identChar(k[i]) && k[i] != ':' && k[i] != '/' && k[i] != '+' {
			return strconv.Quote(k)
		}
	}
	if k == "" {
		return `""`
	}
	return k
}

func fmtSel(v string) string {
	if v == "" || v != strings.TrimSpace(v) || strings.ContainsAny(v, `[]"=`) || !safeText(v) {
		return strconv.Quote(v)
	}
	return v
}

// seqKey: the key that names the items of list n ("" = none: items by value or position).
func seqKey(n *yaml.Node) string {
	if len(n.Content) == 0 || n.Content[0].Kind != yaml.MappingNode {
		return ""
	}
	return listID(n, n)
}

func itemNames(seq *yaml.Node, k string) string {
	var ns []string
	for _, it := range seq.Content {
		if v := mapIndex(it)[k]; v != nil {
			ns = append(ns, v.Value)
		}
	}
	if len(ns) == 0 {
		return "none"
	}
	return strings.Join(ns, ", ")
}

// findItem: the index of the item of seq that st selects.
func findItem(seq *yaml.Node, st pathStep) (int, error) {
	k := st.selK
	if k == "" {
		k = seqKey(seq)
	}
	if k != "" {
		for i, it := range seq.Content {
			if v := mapIndex(it)[k]; v != nil && v.Kind == yaml.ScalarNode && v.Value == st.val {
				return i, nil
			}
		}
		return -1, fmt.Errorf("no item with %s %q (items: %s)", k, st.val, itemNames(seq, k))
	}
	for i, it := range seq.Content {
		if it.Kind == yaml.ScalarNode && it.Value == st.val {
			return i, nil
		}
	}
	if n, err := strconv.Atoi(st.val); err == nil && n >= 0 && n < len(seq.Content) {
		return n, nil
	}
	return -1, fmt.Errorf("no item %q (%d items)", st.val, len(seq.Content))
}

// nodeAt follows steps from root; create adds missing mapping keys (as empty mappings).
func nodeAt(root *yaml.Node, steps []pathStep, create bool) (*yaml.Node, error) {
	n := root
	for i, st := range steps {
		where := fmtPath(steps[:i])
		if where == "" {
			where = "the config"
		}
		if st.sel {
			if n.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("%s is not a list", where)
			}
			j, err := findItem(n, st)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", where, err)
			}
			n = n.Content[j]
			continue
		}
		if n.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s has no keys (it is a %s)", where, kindName(n))
		}
		v := mapIndex(n)[st.key]
		if v == nil {
			if !create {
				return nil, fmt.Errorf("%s has no key %q", where, st.key)
			}
			v = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			n.Content = append(n.Content, strNode(st.key), v)
		}
		n = v
	}
	return n, nil
}

func kindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.SequenceNode:
		return "list"
	case yaml.MappingNode:
		return "mapping"
	}
	return "value"
}

func strNode(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }

func cloneNode(n *yaml.Node) *yaml.Node {
	c := *n
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, x := range n.Content {
		c.Content[i] = cloneNode(x)
	}
	return &c
}

// ---- edits ----

// patchOp is one edit: set PATH to VALUE, add VALUE to the list at PATH, del PATH.
type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value,omitempty"`
	node  *yaml.Node      // the CLI's value, parsed as YAML
}

func (o patchOp) value() (*yaml.Node, error) {
	if o.node != nil {
		return o.node, nil
	}
	if len(o.Value) == 0 {
		return nil, errors.New("value missing")
	}
	var v any
	if err := json.Unmarshal(o.Value, &v); err != nil {
		return nil, err
	}
	b, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var d yaml.Node
	if err := yaml.Unmarshal(b, &d); err != nil || len(d.Content) == 0 {
		return nil, fmt.Errorf("bad value: %v", err)
	}
	return d.Content[0], nil
}

// parseValue reads a CLI value as YAML (true, 8443, "text", [tcp, udp], {name: x, port: "80"}).
func parseValue(s string) (*yaml.Node, error) {
	var d yaml.Node
	if err := yaml.Unmarshal([]byte(s), &d); err != nil {
		return nil, fmt.Errorf("value %q: %v", s, err)
	}
	if len(d.Content) == 0 {
		return strNode(s), nil
	}
	return d.Content[0], nil
}

// applyOp changes tree root (a config's canonical tree) by op.
func applyOp(root *yaml.Node, op patchOp) error {
	steps, err := parsePath(op.Path)
	if err != nil {
		return err
	}
	last := steps[len(steps)-1]
	var val *yaml.Node
	if op.Op == "set" || op.Op == "add" {
		if val, err = op.value(); err != nil {
			return err
		}
	}
	switch op.Op {
	case "set", "add":
		parent, err := nodeAt(root, steps[:len(steps)-1], true)
		if err != nil {
			return err
		}
		var slot **yaml.Node
		switch {
		case last.sel:
			if parent.Kind != yaml.SequenceNode {
				return fmt.Errorf("%s is not a list", fmtPath(steps[:len(steps)-1]))
			}
			j, err := findItem(parent, last)
			if err != nil {
				return err
			}
			slot = &parent.Content[j]
		case parent.Kind != yaml.MappingNode:
			return fmt.Errorf("%s has no keys", fmtPath(steps[:len(steps)-1]))
		default:
			for i := 0; i+1 < len(parent.Content); i += 2 {
				if parent.Content[i].Value == last.key {
					slot = &parent.Content[i+1]
				}
			}
			if slot == nil {
				nv := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
				if op.Op == "set" {
					nv = val
				}
				parent.Content = append(parent.Content, strNode(last.key), nv)
				slot = &parent.Content[len(parent.Content)-1]
			}
		}
		if op.Op == "set" {
			*slot = val
			return nil
		}
		return addItem(*slot, val)
	case "del":
		parent, err := nodeAt(root, steps[:len(steps)-1], false)
		if err != nil {
			return err
		}
		if last.sel {
			if parent.Kind != yaml.SequenceNode {
				return fmt.Errorf("%s is not a list", fmtPath(steps[:len(steps)-1]))
			}
			j, err := findItem(parent, last)
			if err != nil {
				return err
			}
			parent.Content = append(parent.Content[:j], parent.Content[j+1:]...)
			return nil
		}
		if parent.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(parent.Content); i += 2 {
				if parent.Content[i].Value == last.key {
					parent.Content = append(parent.Content[:i], parent.Content[i+2:]...)
					return nil
				}
			}
		}
		return fmt.Errorf("no key %q", last.key)
	}
	return fmt.Errorf("unknown op %q (set | add | del)", op.Op)
}

// addItem appends v to list seq; a named item's name must be new, a value must not be there yet.
func addItem(seq, v *yaml.Node) error {
	if seq.Kind != yaml.SequenceNode {
		return fmt.Errorf("not a list (it is a %s)", kindName(seq))
	}
	if v.Kind == yaml.MappingNode {
		k := seqKey(seq)
		if k == "" && len(seq.Content) == 0 && mapIndex(v)["name"] != nil {
			k = "name"
		}
		if k != "" {
			nm := mapIndex(v)[k]
			if nm == nil || nm.Kind != yaml.ScalarNode || nm.Value == "" {
				return fmt.Errorf("the new item needs a %s", k)
			}
			if _, err := findItem(seq, pathStep{sel: true, selK: k, val: nm.Value}); err == nil {
				return fmt.Errorf("an item with %s %q exists already (set changes it)", k, nm.Value)
			}
		}
	} else if v.Kind == yaml.ScalarNode {
		for _, it := range seq.Content {
			if it.Kind == yaml.ScalarNode && it.Value == v.Value {
				return fmt.Errorf("%q is in the list already", v.Value)
			}
		}
	}
	seq.Content = append(seq.Content, v)
	return nil
}

// pruneTo: full (a normalized tree) with only the mapping keys shape has — values typed as the
// config types them, but no zero values spelled out that the edit did not write.
func pruneTo(full, shape *yaml.Node) *yaml.Node {
	if full == nil || shape == nil || full.Kind != shape.Kind {
		return full
	}
	switch full.Kind {
	case yaml.MappingNode:
		sm := mapIndex(shape)
		c := *full
		c.Content = nil
		for i := 0; i+1 < len(full.Content); i += 2 {
			if s := sm[full.Content[i].Value]; s != nil {
				c.Content = append(c.Content, full.Content[i], pruneTo(full.Content[i+1], s))
			}
		}
		return &c
	case yaml.SequenceNode:
		if len(full.Content) != len(shape.Content) {
			return full
		}
		c := *full
		c.Content = make([]*yaml.Node, len(full.Content))
		for i := range full.Content {
			c.Content[i] = pruneTo(full.Content[i], shape.Content[i])
		}
		return &c
	}
	return full
}

// editYAML applies ops to router.yaml text cur: the new text (only the edited values changed,
// comments and layout kept) and the config it holds (no defaults, no secrets). kept is false when
// the edit could not be made in place and the file had to be written in canonical form.
func editYAML(cur []byte, ops []patchOp) (out []byte, c *Config, kept bool, err error) {
	if len(ops) > 500 {
		return nil, nil, false, errors.New("at most 500 edits at once")
	}
	raw, err := decodeConfig(cur)
	if err != nil {
		return nil, nil, false, err
	}
	base, err := canonNode(raw)
	if err != nil {
		return nil, nil, false, err
	}
	shape := cloneNode(base)
	for _, op := range ops {
		if err := applyOp(shape, op); err != nil {
			return nil, nil, false, fmt.Errorf("%s %s: %w", op.Op, op.Path, err)
		}
	}
	y, err := yaml.Marshal(shape)
	if err != nil {
		return nil, nil, false, err
	}
	want, err := decodeConfig(y)
	if err != nil {
		return nil, nil, false, fmt.Errorf("the result does not fit router.yaml: %w", err)
	}
	full, err := canonNode(want)
	if err != nil {
		return nil, nil, false, err
	}
	out, err = mergeYAML(cur, base, pruneTo(full, shape))
	if err == nil && !bytes.HasSuffix(cur, []byte("\n\n")) {
		for bytes.HasSuffix(out, []byte("\n\n")) { // the blank line before a section removed at the end
			out = out[:len(out)-1]
		}
	}
	if err == nil {
		var got *Config
		if got, err = decodeConfig(out); err == nil {
			if gn, _ := canonNode(got); !nodeEqual(gn, full) {
				err = errors.New("edited file would not hold the new config")
			}
		}
	}
	if err != nil {
		b, _ := yaml.Marshal(want)
		return append([]byte("# written by mr (the edit could not be made in place: "+firstLine(err.Error())+")\n"), b...), want, false, nil
	}
	return out, want, true, nil
}

// ---- CLI: mr get / set / add / del / export ----

// splitAssign splits PATH=VALUE at the first = outside brackets and quotes.
func splitAssign(s string) (string, string, bool) {
	depth, q := 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case q && c == '\\':
			i++
		case c == '"':
			q = !q
		case q:
		case c == '[':
			depth++
		case c == ']':
			depth--
		case c == '=' && depth == 0:
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// cfgCommand is `mr get [PATH] [--json|--flat]`, `mr export [--json|--flat]`,
// `mr set [-n] PATH=VALUE...`, `mr add [-n] PATH VALUE`, `mr del [-n] PATH...`.
func cfgCommand(cmd string, args []string, cfgPath, secPath string) error {
	var asJSON, flat, dry bool
	var rest []string
	for _, a := range args { // flags anywhere: mr get PATH --json
		switch strings.TrimLeft(a, "-") {
		case "json":
			asJSON = true
		case "flat":
			flat = true
		case "n", "dry-run":
			dry = true
		default:
			if strings.HasPrefix(a, "-") && !strings.Contains(a, "=") {
				return fmt.Errorf("%s: unknown flag %s", cmd, a)
			}
			rest = append(rest, a)
		}
	}
	args = rest
	switch cmd {
	case "get", "export":
		c, err := loadConfig(cfgPath, secPath)
		if err != nil {
			return err
		}
		root, err := canonNode(c)
		if err != nil {
			return err
		}
		prefix := ""
		if cmd == "get" && len(args) > 0 {
			steps, err := parsePath(args[0])
			if err != nil {
				return err
			}
			if root, err = nodeAt(root, steps, false); err != nil {
				return err
			}
			prefix = fmtPath(steps)
		}
		switch {
		case flat:
			for _, l := range flatLines(root, prefix) {
				fmt.Println(l)
			}
		case asJSON:
			var v any
			if err := root.Decode(&v); err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(v)
		case root.Kind == yaml.ScalarNode:
			fmt.Println(root.Value)
		default:
			b, err := yaml.Marshal(root)
			if err != nil {
				return err
			}
			os.Stdout.Write(b)
		}
		return nil
	}
	var ops []patchOp
	switch cmd {
	case "set":
		for _, a := range args {
			p, v, ok := splitAssign(a)
			if !ok {
				return fmt.Errorf("set PATH=VALUE, got %q", a)
			}
			n, err := parseValue(v)
			if err != nil {
				return err
			}
			ops = append(ops, patchOp{Op: "set", Path: p, node: n})
		}
	case "add":
		if len(args) != 2 {
			return errors.New("add PATH VALUE (a list item, e.g. '{name: web, proto: [tcp], port: \"8443\", to: 192.168.1.20}')")
		}
		n, err := parseValue(args[1])
		if err != nil {
			return err
		}
		ops = append(ops, patchOp{Op: "add", Path: args[0], node: n})
	case "del":
		for _, a := range args {
			ops = append(ops, patchOp{Op: "del", Path: a})
		}
	}
	if len(ops) == 0 {
		return fmt.Errorf("%s: nothing to do", cmd)
	}
	changes, out, kept, err := editFile(cfgPath, secPath, ops)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		fmt.Println("no change")
		return nil
	}
	fmt.Print("changes:\n  " + strings.Join(changes, "\n  ") + "\n")
	if dry {
		return nil
	}
	if cfgPath == ConfigPath {
		if err := pendingBlocks(); err != nil { // its rollback would silently undo this edit
			return fmt.Errorf("%v (router.yaml not changed)", err)
		}
	}
	if !kept {
		fmt.Fprintln(os.Stderr, "note: this edit could not be made in place; router.yaml is written in canonical form (comments not kept)")
	}
	mode := os.FileMode(0644)
	if st, err := os.Stat(cfgPath); err == nil {
		mode = st.Mode().Perm()
	}
	if err := writeAtomic(cfgPath, out, mode); err != nil {
		return err
	}
	fmt.Println("router.yaml changed (not applied yet): `mr plan`, then `mr apply --confirm 120` and `mr confirm`")
	return nil
}

// editFile applies ops to the router.yaml at cfgPath (not written): the config-level changes, the new
// text, whether the layout was kept. The result must validate.
func editFile(cfgPath, secPath string, ops []patchOp) ([]string, []byte, bool, error) {
	cur, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, nil, false, err
	}
	out, want, kept, err := editYAML(cur, ops)
	if err != nil {
		return nil, nil, false, err
	}
	old, err := loadConfig(cfgPath, secPath)
	if err != nil {
		return nil, nil, false, err
	}
	want.secrets = old.secrets
	want.defaults()
	if errs := want.Validate(); len(errs) > 0 {
		return nil, nil, false, fmt.Errorf("not changed, the result is invalid:\n  %s", strings.Join(errs, "\n  "))
	}
	a, err := canonNode(old)
	if err != nil {
		return nil, nil, false, err
	}
	b, err := canonNode(want)
	if err != nil {
		return nil, nil, false, err
	}
	return configChanges(a, b), out, kept, nil
}

// flatLines: every value under n as PATH=VALUE (lists of values and empty collections on one line).
func flatLines(n *yaml.Node, path string) []string {
	switch {
	case n.Kind == yaml.MappingNode && len(n.Content) > 0:
		var out []string
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := fmtKey(n.Content[i].Value)
			if path != "" {
				k = path + "." + k
			}
			out = append(out, flatLines(n.Content[i+1], k)...)
		}
		return out
	case n.Kind == yaml.SequenceNode && !isInline(n):
		var out []string
		k := seqKey(n)
		for i, it := range n.Content {
			sel := strconv.Itoa(i)
			if k != "" {
				sel = fmtSel(mapIndex(it)[k].Value)
			}
			out = append(out, flatLines(it, path+"["+sel+"]")...)
		}
		return out
	}
	return []string{path + "=" + renderFlow(n)}
}

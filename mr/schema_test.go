package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// schemaCheck: the problems of value v (decoded YAML) against schema s — types, enums, unknown and
// required keys.
func schemaCheck(s map[string]any, v any, path string, errs *[]string) {
	bad := func(f string, a ...any) { *errs = append(*errs, path+": "+fmt.Sprintf(f, a...)) }
	switch s["type"] {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			bad("want an object, got %T", v)
			return
		}
		props, _ := s["properties"].(map[string]any)
		for k, x := range m {
			if ps, ok := props[k].(map[string]any); ok {
				schemaCheck(ps, x, path+"."+k, errs)
			} else if ap, ok := s["additionalProperties"].(map[string]any); ok {
				schemaCheck(ap, x, path+"."+k, errs)
			} else {
				bad("unknown key %q", k)
			}
		}
		req, _ := s["required"].([]string)
		for _, k := range req {
			if _, ok := m[k]; !ok {
				bad("required key %q missing", k)
			}
		}
	case "array":
		l, ok := v.([]any)
		if !ok {
			bad("want a list, got %T", v)
			return
		}
		for i, x := range l {
			schemaCheck(s["items"].(map[string]any), x, fmt.Sprintf("%s[%d]", path, i), errs)
		}
	case "string":
		str, ok := v.(string)
		if !ok {
			bad("want a string, got %T", v)
			return
		}
		if e, ok := s["enum"].([]string); ok && !contains(e, str) {
			bad("%q not in %v", str, e)
		}
	case "integer":
		if _, ok := v.(int); !ok {
			bad("want an integer, got %T", v)
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			bad("want a boolean, got %T", v)
		}
	default:
		bad("schema without type")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func labConfig(t *testing.T) *Config {
	t.Helper()
	src, sf := labYAML(t)
	p := filepath.Join(t.TempDir(), "lab.yaml")
	os.WriteFile(p, []byte(src), 0644)
	c, err := loadConfig(p, sf)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The schema describes the effective home and lab configs (every feature on) exactly.
func TestSchemaDescribesConfigs(t *testing.T) {
	s := configSchema()
	for name, c := range map[string]*Config{"home": testConfig(t), "lab": labConfig(t)} {
		n, err := canonNode(c)
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := n.Decode(&v); err != nil {
			t.Fatal(err)
		}
		var errs []string
		schemaCheck(s, v, name, &errs)
		if len(errs) > 0 {
			t.Errorf("%s config against the schema:\n%s", name, strings.Join(errs, "\n"))
		}
	}
	// a few landmarks
	if w, err := schemaAt(s, "wan[x].proto"); err != nil || !reflect.DeepEqual(w["enum"], []string{"pppoe", "dhcp", "static"}) {
		t.Errorf("wan[].proto: %v %v", w, err)
	}
	if w, err := schemaAt(s, "wan[x].password_secret"); err != nil || !strings.Contains(fmt.Sprint(w["description"]), "secrets.yaml") {
		t.Errorf("secret fields are not described: %v %v", w, err)
	}
	if w, err := schemaAt(s, "dhcp"); err != nil || w["properties"].(map[string]any)["dns"] == nil {
		t.Errorf("inline DHCPOpts not merged: %v", err)
	}
	if w, err := schemaAt(s, `system.sysctl."net.core.rmem_max"`); err != nil || w["type"] != "string" {
		t.Errorf("sysctl values: %v %v", w, err)
	}
	if _, err := schemaAt(s, "lan.nosuch"); err == nil {
		t.Error("unknown path accepted")
	}
}

// Every enum names a real field; the configs only use listed values; a value outside the set fails
// validation (so the set is enforced, not only documented).
func TestSchemaEnums(t *testing.T) {
	fields := map[string]bool{}
	var collect func(t reflect.Type)
	collect = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || fields[t.Name()] {
			return
		}
		fields[t.Name()] = true
		for i := 0; i < t.NumField(); i++ {
			fields[t.Name()+"."+t.Field(i).Name] = true
			collect(t.Field(i).Type)
		}
	}
	collect(reflect.TypeOf(Config{}))
	keys := []string{}
	for k := range schemaEnums() {
		keys = append(keys, k)
		if !fields[k] {
			t.Errorf("schemaEnums: no field %s", k)
		}
	}
	sort.Strings(keys)
	used := map[string]bool{}
	for _, c := range []*Config{testConfig(t), labConfig(t)} {
		walkFields(reflect.ValueOf(c).Elem(), func(key string, f reflect.Value) bool {
			if e, ok := schemaEnums()[key]; ok {
				used[key] = true
				for _, s := range stringsOf(f) {
					if !contains(e, s) {
						t.Errorf("%s = %q is not in its enum %v", key, s, e)
					}
				}
			}
			return false
		})
	}
	for _, key := range keys {
		if !used[key] {
			t.Logf("%s: not in the lab config, validation not checked", key)
			continue
		}
		c := labConfig(t)
		walkFields(reflect.ValueOf(c).Elem(), func(k string, f reflect.Value) bool {
			if k != key {
				return false
			}
			if f.Kind() == reflect.Slice {
				if f.Len() == 0 {
					return false
				}
				f = f.Index(0)
			}
			f.SetString("bogus-value")
			return true
		})
		if errs := c.Validate(); len(errs) == 0 {
			t.Errorf("%s = \"bogus-value\" passes validation", key)
		}
	}
}

// walkFields calls f with "<type>.<field>" and the value of every field of every struct under v,
// until f returns true.
func walkFields(v reflect.Value, f func(key string, fv reflect.Value) bool) bool {
	switch v.Kind() {
	case reflect.Pointer:
		return !v.IsNil() && walkFields(v.Elem(), f)
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if walkFields(v.Index(i), f) {
				return true
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !v.Type().Field(i).IsExported() {
				continue
			}
			if f(v.Type().Name()+"."+v.Type().Field(i).Name, v.Field(i)) || walkFields(v.Field(i), f) {
				return true
			}
		}
	}
	return false
}

func stringsOf(v reflect.Value) []string {
	switch v.Kind() {
	case reflect.String:
		return []string{v.String()}
	case reflect.Slice:
		var out []string
		for i := 0; i < v.Len(); i++ {
			out = append(out, stringsOf(v.Index(i))...)
		}
		return out
	}
	return nil
}

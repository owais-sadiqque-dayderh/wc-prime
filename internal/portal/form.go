package portal

import (
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

type token struct {
	tag, text string
	attrs     map[string]string
	end       bool
}

// tokenize handles the small subset of HTML used by portal forms. Script and
// style bodies are raw text, so embedded markup cannot become form controls.
func tokenize(src string) []token {
	var out []token
	for len(src) > 0 {
		if !strings.HasPrefix(src, "<") {
			n := strings.IndexByte(src, '<')
			if n < 0 {
				n = len(src)
			}
			out = append(out, token{text: html.UnescapeString(src[:n])})
			src = src[n:]
			continue
		}
		if strings.HasPrefix(src, "<!--") {
			n := strings.Index(src, "-->")
			if n < 0 {
				break
			}
			src = src[n+3:]
			continue
		}
		n := 1
		var quote byte
		for n < len(src) {
			b := src[n]
			if quote != 0 {
				if b == quote {
					quote = 0
				}
			} else if b == '\'' || b == '"' {
				quote = b
			} else if b == '>' {
				break
			}
			n++
		}
		if n == len(src) {
			break
		}
		raw := strings.TrimSpace(src[1:n])
		src = src[n+1:]
		t := token{attrs: make(map[string]string)}
		if strings.HasPrefix(raw, "/") {
			t.end = true
			raw = strings.TrimSpace(raw[1:])
		}
		i := 0
		for i < len(raw) && !space(raw[i]) && raw[i] != '/' {
			i++
		}
		t.tag = strings.ToLower(raw[:i])
		raw = raw[i:]
		if t.tag == "" || strings.HasPrefix(t.tag, "!") || strings.HasPrefix(t.tag, "?") {
			continue
		}
		for len(raw) > 0 {
			raw = strings.TrimLeftFunc(raw, unicode.IsSpace)
			if raw == "" || raw == "/" {
				break
			}
			i = 0
			for i < len(raw) && !space(raw[i]) && raw[i] != '=' && raw[i] != '/' {
				i++
			}
			if i == 0 {
				raw = raw[1:]
				continue
			}
			key := strings.ToLower(raw[:i])
			raw = strings.TrimLeftFunc(raw[i:], unicode.IsSpace)
			val := ""
			if strings.HasPrefix(raw, "=") {
				raw = strings.TrimLeftFunc(raw[1:], unicode.IsSpace)
				if len(raw) > 0 && (raw[0] == '\'' || raw[0] == '"') {
					q := raw[0]
					raw = raw[1:]
					i = strings.IndexByte(raw, q)
					if i < 0 {
						i = len(raw)
					}
					val = raw[:i]
					raw = raw[i:]
					if len(raw) > 0 {
						raw = raw[1:]
					}
				} else {
					i = 0
					for i < len(raw) && !space(raw[i]) {
						i++
					}
					val = raw[:i]
					raw = raw[i:]
					// A slash separated from a value is handled above; URL slashes are data.
				}
			}
			t.attrs[key] = html.UnescapeString(val)
		}
		out = append(out, t)
		if !t.end && (t.tag == "script" || t.tag == "style" || t.tag == "textarea" || t.tag == "title") {
			end := strings.Index(strings.ToLower(src), "</"+t.tag)
			if end < 0 {
				if t.tag == "textarea" || t.tag == "title" {
					out = append(out, token{text: html.UnescapeString(src)})
				}
				break
			}
			if t.tag == "textarea" || t.tag == "title" {
				out = append(out, token{text: html.UnescapeString(src[:end])})
			}
			src = src[end:]
		}
	}
	return out
}

func space(b byte) bool                      { return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f' }
func has(a map[string]string, k string) bool { _, ok := a[k]; return ok }

type field struct {
	name, id, kind, value string
	checked               bool
}
type form struct {
	action, method string
	fields         []field
	submit         bool
}
type page struct {
	forms          []form
	refresh, title string
}

func parsePage(src string) page {
	ts := tokenize(src)
	var p page
	current := -1
	for i := 0; i < len(ts); i++ {
		t := ts[i]
		if t.tag == "title" && !t.end {
			var b strings.Builder
			for i++; i < len(ts) && !(ts[i].tag == "title" && ts[i].end); i++ {
				b.WriteString(ts[i].text)
			}
			p.title = strings.Join(strings.Fields(b.String()), " ")
			continue
		}
		if t.tag == "meta" && !t.end && strings.EqualFold(t.attrs["http-equiv"], "refresh") {
			if m := refreshRE.FindStringSubmatch(t.attrs["content"]); len(m) > 1 {
				p.refresh = strings.Trim(strings.TrimSpace(m[1]), "\"'")
			}
		}
		if t.tag == "form" {
			if t.end {
				current = -1
			} else {
				p.forms = append(p.forms, form{action: t.attrs["action"], method: t.attrs["method"]})
				current = len(p.forms) - 1
			}
			continue
		}
		if current < 0 || t.end {
			continue
		}
		f := field{name: t.attrs["name"], id: t.attrs["id"], value: t.attrs["value"], kind: strings.ToLower(t.attrs["type"]), checked: has(t.attrs, "checked")}
		disabled := has(t.attrs, "disabled")
		switch t.tag {
		case "input":
			if f.kind == "" {
				f.kind = "text"
			}
			if f.kind == "submit" || f.kind == "image" {
				if !disabled {
					p.forms[current].submit = true
				}
			} else if f.kind == "button" || f.kind == "reset" || f.kind == "file" {
				continue
			}
		case "button":
			if f.kind != "" && f.kind != "submit" {
				continue
			}
			f.kind = "submit"
			if !disabled {
				p.forms[current].submit = true
			}
		case "textarea":
			f.kind = "textarea"
			var b strings.Builder
			for i++; i < len(ts) && !(ts[i].tag == "textarea" && ts[i].end); i++ {
				b.WriteString(ts[i].text)
			}
			f.value = b.String()
		case "select":
			f.kind = "select"
			var first, selected string
			haveFirst, haveSelected := false, false
			for i++; i < len(ts) && !(ts[i].tag == "select" && ts[i].end); {
				o := ts[i]
				if o.tag != "option" || o.end {
					i++
					continue
				}
				i++
				var b strings.Builder
				for i < len(ts) && ts[i].tag != "option" && !(ts[i].tag == "select" && ts[i].end) {
					b.WriteString(ts[i].text)
					i++
				}
				v := o.attrs["value"]
				if !has(o.attrs, "value") {
					v = strings.TrimSpace(b.String())
				}
				if !has(o.attrs, "disabled") {
					if !haveFirst {
						first = v
						haveFirst = true
					}
					if has(o.attrs, "selected") && !haveSelected {
						selected = v
						haveSelected = true
					}
				}
			}
			f.value = first
			if haveSelected {
				f.value = selected
			}
		default:
			continue
		}
		if !disabled && f.name != "" {
			p.forms[current].fields = append(p.forms[current].fields, f)
		}
	}
	return p
}

var (
	refreshRE = regexp.MustCompile(`(?i)(?:^|;)\s*url\s*=\s*(.*)$`)
	userRE    = regexp.MustCompile(`(?i)user|login|email|uname|uid|account|auth|roll|mobile|phone|id|name`)
	termsRE   = regexp.MustCompile(`(?i)terms|agree|accept|tos|policy|aup|consent`)
)

func (f form) password(c Creds) bool {
	for _, v := range f.fields {
		if v.kind == "password" || (c.PassField != "" && v.name == c.PassField) {
			return true
		}
	}
	return false
}
func userScore(f field) int {
	switch f.kind {
	case "text", "email", "tel", "number":
	default:
		return 0
	}
	if strings.EqualFold(f.name, "username") || strings.EqualFold(f.id, "username") {
		return 100
	}
	if userRE.MatchString(f.name + " " + f.id) {
		return 10
	}
	return 0
}
func chooseForm(p page, c Creds) (form, bool) {
	for _, f := range p.forms {
		if f.password(c) {
			return f, true
		}
	}
	for _, f := range p.forms {
		for _, v := range f.fields {
			if (c.UserField != "" && v.name == c.UserField) || userScore(v) > 0 {
				return f, true
			}
		}
	}
	for _, f := range p.forms {
		if f.submit {
			return f, true
		}
	}
	return form{}, false
}

type pair struct{ key, value string }

func fill(f form, c Creds) []pair {
	user := -1
	best := -1
	beforePass := true
	for i, v := range f.fields {
		if v.kind == "password" || (c.PassField != "" && v.name == c.PassField) {
			beforePass = false
			continue
		}
		if c.UserField != "" {
			if v.name == c.UserField {
				user = i
			}
			continue
		}
		score := userScore(v)
		if score == 0 {
			switch v.kind {
			case "text", "email", "tel", "number":
				score = 1
			default:
				continue
			}
		}
		if beforePass {
			score += 20
		}
		if score > best {
			best = score
			user = i
		}
	}
	checked := map[string]bool{}
	for _, v := range f.fields {
		if v.kind == "radio" && v.checked {
			checked[v.name] = true
		}
	}
	var values []pair
	submitted := false
	radioSeen := map[string]bool{}
	for i, v := range f.fields {
		switch v.kind {
		case "submit", "image":
			if submitted {
				continue
			}
			submitted = true
		case "checkbox":
			if !v.checked && !termsRE.MatchString(v.name+" "+v.id) {
				continue
			}
			if v.value == "" {
				v.value = "on"
			}
		case "radio":
			if !v.checked && (checked[v.name] || radioSeen[v.name]) {
				continue
			}
			radioSeen[v.name] = true
			if v.value == "" {
				v.value = "on"
			}
		}
		if v.kind == "password" || (c.PassField != "" && v.name == c.PassField) {
			v.value = c.Password
		} else if i == user {
			v.value = c.Username
		}
		values = append(values, pair{v.name, v.value})
	}
	keys := make([]string, 0, len(c.Extra))
	for k := range c.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		found := false
		for i := range values {
			if values[i].key == k {
				values[i].value = c.Extra[k]
				found = true
			}
		}
		if !found {
			values = append(values, pair{k, c.Extra[k]})
		}
	}
	return values
}
func encode(values []pair) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, url.QueryEscape(v.key)+"="+url.QueryEscape(v.value))
	}
	return strings.Join(parts, "&")
}

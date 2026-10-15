package portal

import (
	"reflect"
	"testing"
)

func TestParseAndFill(t *testing.T) {
	tests := []struct {
		name, html string
		creds      Creds
		want       string
	}{
		{"quoting and entities", `<!-- <form> --> <FORM ACTION='/login?a=1&amp;b=2' METHOD=POST><INPUT TYPE=hidden NAME=csrf VALUE='a&amp;b'/><input name=username><input type=PASSWORD name=p><input type=submit name=go value="Sign in"><input type=submit name=other value=no></FORM>`, Creds{Username: "alice", Password: "s&cret"}, "csrf=a%26b&username=alice&p=s%26cret&go=Sign+in"},
		{"select textarea buttons", `<form><select name=zone><option value=a>A<option selected value='b&amp;c'>B</select><select name=first><option> First &amp; One </option><option value=two>Two</select><textarea name=note>Hello &lt;world&gt;</textarea><button type=button name=skip>Skip</button><button name=go value=yes>Continue</button><input type=reset name=reset><input disabled name=disabled value=x></form>`, Creds{}, "zone=b%26c&first=First+%26+One&note=Hello+%3Cworld%3E&go=yes"},
		{"terms and radios", `<form><input type=checkbox name=normal><input type=checkbox name=agree_policy><input type=checkbox name=check checked value=yes><input type=radio name=plan value=one><input type=radio name=plan value=two><input type=radio name=other value=a><input type=radio name=other value=b checked><button>Go</button></form>`, Creds{}, "agree_policy=on&check=yes&plan=one&other=b"},
		{"overrides and extras", `<form><input type=hidden name=csrf value=old><input name=custom><input name=pin type=number><input name=username><input type=password name=secret><button name=submit value=go></form>`, Creds{Username: "user", Password: "pass", UserField: "custom", PassField: "pin", Extra: map[string]string{"csrf": "new", "extra": "yes"}}, "csrf=new&custom=user&pin=pass&username=&secret=pass&submit=go&extra=yes"},
		{"username ranking", `<form><input type=hidden name=username value=token><input name=account><input name=username><input type=password name=pw><input name=email><button>Go</button></form>`, Creds{Username: "user", Password: "pass"}, "username=token&account=&username=user&pw=pass&email="},
		{"generic username", `<form><input name=field1><input type=password name=field2><input name=field3></form>`, Creds{Username: "u", Password: "p"}, "field1=u&field2=p&field3="},
		{"raw textarea", `<form><textarea name=note><b>A &amp; B</b></textarea><button>Go</button></form>`, Creds{}, "note=%3Cb%3EA+%26+B%3C%2Fb%3E"},
		{"skip scripts and styles", `<script>var x='<form><input type=password name=fake>';</script><style>.x{content:'<form>'}</style><form><input name=user><input type=password name=pw></form>`, Creds{Username: "u", Password: "p"}, "user=u&pw=p"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := parsePage(tt.html)
			if len(p.forms) != 1 {
				t.Fatalf("forms: %#v", p.forms)
			}
			got := encode(fill(p.forms[0], tt.creds))
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPageMetadata(t *testing.T) {
	p := parsePage(`<TITLE> Login &amp; Access </TITLE><META HTTP-EQUIV=Refresh content="0; URL='/next?a=1&amp;b=2'"><form action='/login?a=1&amp;b=2' method=GET><input name=x /></form>`)
	if p.title != "Login & Access" || p.refresh != "/next?a=1&b=2" {
		t.Fatalf("metadata: %#v", p)
	}
	if p.forms[0].action != "/login?a=1&b=2" || p.forms[0].method != "GET" {
		t.Fatalf("form: %#v", p.forms[0])
	}
}

func TestChooseForm(t *testing.T) {
	for _, tt := range []struct{ html, want string }{
		{`<form action=a><button>Go</button></form><form action=b><input name=user></form><form action=c><input type=password name=p></form>`, "c"},
		{`<form action=a><button>Go</button></form><form action=b><input name=email></form>`, "b"},
		{`<form action=a><input name=x></form><form action=b><button>Go</button></form>`, "b"},
	} {
		f, ok := chooseForm(parsePage(tt.html), Creds{})
		if !ok || f.action != tt.want {
			t.Fatalf("got %#v, %v; want %s", f, ok, tt.want)
		}
	}
}

func TestFieldOrder(t *testing.T) {
	f := parsePage(`<form><input name=x value=1><input name=x value=2><input type=password name=p></form>`).forms[0]
	got := fill(f, Creds{Password: "p", Extra: map[string]string{"x": "override", "z": "last"}})
	want := []pair{{"x", "override"}, {"x", "override"}, {"p", "p"}, {"z", "last"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

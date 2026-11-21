package handler

import "testing"

// csvText must catch a formula however a spreadsheet importer might see it:
// importers can drop a BOM, control character or space before looking at the
// first character, so the check runs on the cleaned string and the invisible
// prefix is not kept.
func TestCSVText(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"=1+1", "'=1+1"}, {"+27821234567", "'+27821234567"}, {"-5", "'-5"}, {"@cmd", "'@cmd"}, {"\t=1", "'=1"}, {"\r=1", "'=1"},
		{"\ufeff=1", "'=1"}, {"\x00\u200b+27", "'+27"}, {" =1", "'=1"}, {"\tplain", "'plain"}, {"\ufeffplain", "'plain"},
		{`"quotes"`, `"quotes"`}, {"a,b", "a,b"}, {"a\nb", "a\nb"}, {"你好", "你好"}, {"", ""}, {"ordinary", "ordinary"},
	} {
		if got := csvText(tc.in); got != tc.want {
			t.Errorf("csvText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

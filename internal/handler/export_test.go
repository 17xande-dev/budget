package handler_test

import (
	"encoding/csv"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/17xande-dev/budget/internal/importer"
	"github.com/17xande-dev/budget/internal/ledger"
)

// A merchant names itself; a description beginning "=" must reach a spreadsheet
// as text, never as a live formula.
const formulaCSV = `ACCOUNT TRANSACTION HISTORY

Name:, Test, Person
Account:, 62000000009, [Cheque Acc]
Balance:, 100.00, 100.00

Date, Amount, Balance, Description
2026/10/03, -10.00, 100.00, =HYPERLINK("http://evil.example","click")
2026/10/02, -20.00, 110.00, @SUM(A1:A9)
2026/10/01, -30.00, 130.00, PLAIN SHOP
`

func TestTransactionsCSV(t *testing.T) {
	_, owner := seeded(t)
	owner.upload(map[string][]byte{"formula.csv": []byte(formulaCSV)})

	r := owner.get("/transactions.csv?month=all")
	if r.code != http.StatusOK || !strings.HasPrefix(r.hdr.Get("Content-Type"), "text/csv") ||
		!strings.Contains(r.hdr.Get("Content-Disposition"), `filename="transactions-all.csv"`) {
		t.Fatalf("export: %d %v", r.code, r.hdr)
	}
	rows, err := csv.NewReader(strings.NewReader(r.body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 10 || rows[0][0] != "Date" || rows[0][3] != "Amount" {
		t.Fatalf("%d rows, header %v", len(rows), rows[0])
	}
	// Oldest first, as a ledger reads.
	if rows[1][0] > rows[len(rows)-1][0] {
		t.Errorf("not oldest first: %s .. %s", rows[1][0], rows[len(rows)-1][0])
	}
	// Within a day the bank's order survives, so the running balance reads
	// correctly: the cheque fixture's two same-day Checkers rows, 10339.90 then 10250.00.
	var checkers []string
	for _, row := range rows[1:] {
		if strings.HasPrefix(row[2], "CHECKERS") {
			checkers = append(checkers, row[4])
		}
	}
	if len(checkers) != 2 || checkers[0] != "10339.90" || checkers[1] != "10250.00" {
		t.Errorf("same-day rows out of order: balances %v", checkers)
	}
	descs := map[string]bool{}
	for _, row := range rows[1:] {
		descs[row[2]] = true
		// Amounts are ours: numbers, unescaped, so a spreadsheet can sum them.
		if strings.HasPrefix(row[3], "'") {
			t.Errorf("amount escaped: %v", row)
		}
		for _, cell := range []string{row[1], row[2], row[5]} {
			if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
				t.Errorf("live formula cell %q", cell)
			}
		}
	}
	if !descs[`'=HYPERLINK("http://evil.example","click")`] || !descs["'@SUM(A1:A9)"] || !descs["PLAIN SHOP"] {
		t.Errorf("descriptions not escaped as expected: %v", descs)
	}
	// The page's link exports what the page shows: here the latest month only.
	page := owner.get("/transactions").body
	if !strings.Contains(page, `href="/transactions.csv?month=2026-10"`) {
		t.Error("the page's export link is not its resolved filter")
	}
	month := owner.get("/transactions.csv?month=2026-10&q=plain")
	if rows, _ := csv.NewReader(strings.NewReader(month.body)).ReadAll(); len(rows) != 2 || rows[1][2] != "PLAIN SHOP" {
		t.Errorf("filtered export: %v", rows)
	}
}

// A spreadsheet importer can drop a leading space or BOM before it decides a cell
// is a formula, so a description that starts with one must be defused too, with
// the invisible prefix removed. The statement importer collapses and trims
// whitespace, so a stored description cannot be fed through an upload here: it is
// written with the ledger store, the same call the upload makes, and read back
// through the real download route.
func TestTransactionsCSVDefusesHiddenPrefixFormulas(t *testing.T) {
	e := newEnv(t)
	owner := e.claim()
	st := importer.Statement{AccountRef: "62000000009", AccountLabel: "Cheque Acc", Format: "csv", Txns: []importer.Txn{
		{Date: "2026-10-04", AmountCents: -4000, Description: " =1"},
		{Date: "2026-10-05", AmountCents: -5000, Description: "\ufeff=HYPERLINK(1)"},
		{Date: "2026-10-06", AmountCents: -6000, Description: "PLAIN SHOP"},
	}}
	if _, err := ledger.NewStore(e.db).Import(st, ledger.SourceUpload, "hidden.csv", 0, time.Now()); err != nil {
		t.Fatal(err)
	}

	r := owner.get("/transactions.csv?month=all")
	rows, err := csv.NewReader(strings.NewReader(r.body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	descs := map[string]bool{}
	for _, row := range rows[1:] {
		descs[row[2]] = true
	}
	if !descs["'=1"] || !descs["'=HYPERLINK(1)"] || !descs["PLAIN SHOP"] {
		t.Errorf("hidden-prefix formulas not escaped: %v", descs)
	}
}

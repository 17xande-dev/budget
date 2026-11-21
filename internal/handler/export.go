package handler

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/17xande-dev/budget/internal/ledger"
	"github.com/17xande-dev/budget/internal/money"
	"github.com/17xande-dev/websec"
)

// maxExport caps one CSV. Years of a household's transactions are tens of
// thousands of rows; the cap is there so a mistake cannot build an unbounded
// buffer, and it refuses rather than truncating, because a short export looks
// exactly like a complete one.
const maxExport = 200_000

// TransactionsCSV downloads the transactions a filter selects (the same filter as
// the page), oldest first, for a spreadsheet or for keeping.
//
// The whole file is built in memory before any header is written: streaming
// would commit a 200 before the query could fail, handing over a truncated file
// that looks like a good one.
func (h *Handler) TransactionsCSV(w http.ResponseWriter, r *http.Request) {
	months, err := h.ledger.Months()
	if err != nil {
		h.fail(w, "export: months", err)
		return
	}
	accts, err := h.ledger.Accounts()
	if err != nil {
		h.fail(w, "export: accounts", err)
		return
	}
	cats, err := h.budget.Categories(true)
	if err != nil {
		h.fail(w, "export: categories", err)
		return
	}
	f, _ := txnFilter(r.URL.Query(), months, accts, cats)
	tot, err := h.ledger.Totals(f)
	if err != nil {
		h.fail(w, "export: totals", err)
		return
	}
	if tot.Count > maxExport {
		http.Error(w, fmt.Sprintf("That is %d transactions, more than one export holds (%d). Choose a month or an account.", tot.Count, maxExport), http.StatusRequestEntityTooLarge)
		return
	}
	txns, err := h.ledger.Transactions(f, maxExport)
	if err != nil {
		h.fail(w, "export: list", err)
		return
	}

	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	cw.Write([]string{"Date", "Account", "Description", "Amount", "Balance", "Category", "Categorised by"})
	// Oldest day first, as a ledger reads. Only the days are reordered: within
	// one day the rows keep the page's order, which for FNB's exports is the
	// order the bank lists them, so running balances still read correctly.
	slices.SortStableFunc(txns, func(a, b ledger.Txn) int { return strings.Compare(a.PostedOn, b.PostedOn) })
	for _, t := range txns {
		bal := ""
		if t.BalanceCents.Valid {
			bal = money.Decimal(t.BalanceCents.Int64)
		}
		// Descriptions are written by merchants, so a text cell goes through
		// websec.CSVCell (a spreadsheet would run a leading "=", "+", "-" or "@").
		// Numbers are ours and never pass through it, so a negative amount stays
		// a number.
		cw.Write([]string{
			t.PostedOn, websec.CSVCell(t.AccountName), websec.CSVCell(t.Description),
			money.Decimal(t.AmountCents), bal, websec.CSVCell(t.CategoryName), t.CategorySource,
		})
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		h.fail(w, "export: write", err)
		return
	}

	name := "transactions-" + exportName(f) + ".csv"
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write(buf.Bytes())
}

// exportName is a filename part naming the period; only characters we chose.
func exportName(f ledger.Filter) string {
	if f.Month != "" {
		return f.Month
	}
	return "all"
}

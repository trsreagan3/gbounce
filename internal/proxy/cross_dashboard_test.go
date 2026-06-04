package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCrossDashboard_ServesHTMLThatPollsCrossEvents(t *testing.T) {
	srv := httptest.NewServer(crossDashboardHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type=%q; want text/html", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	for _, want := range []string{
		"cross-bouncer view",
		"/cross/events", // the page must poll the data endpoint
		"coverage",      // renders the honest coverage banner
		"id=\"rows\"",   // the events table body
	} {
		if !strings.Contains(s, want) {
			t.Errorf("dashboard HTML missing %q", want)
		}
	}
}

func TestCrossDashboard_RejectsNonGET(t *testing.T) {
	rec := httptest.NewRecorder()
	crossDashboardHandler()(rec, httptest.NewRequest(http.MethodPost, "/cross", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST should be 405; got %d", rec.Code)
	}
}

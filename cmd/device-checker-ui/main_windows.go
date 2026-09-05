//go:build windows

// device-checker-ui presents local posture through a short-lived loopback
// page. It deliberately binds only to 127.0.0.1, opens the user's normal
// browser, and has no network listener after its short preview lifetime.
package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/hackzero/device-checker/internal/posture"
	"github.com/hackzero/device-checker/internal/probe"
)

var version = "dev"

type screenRow struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Status string `json:"status"`
}

type screenModel struct {
	Title       string      `json:"title"`
	Description string      `json:"description"`
	CheckedAt   string      `json:"checkedAt"`
	Rows        []screenRow `json:"rows"`
}

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", servePage)
	mux.HandleFunc("/api/status", serveStatus)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	url := "http://" + listener.Addr().String()
	// rundll32 delegates to the user's default browser and does not create a
	// terminal. It receives no credentials and no report data in the URL.
	if err := exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start(); err != nil {
		return
	}
	go func() { _ = server.Serve(listener) }()
	// This is a temporary local UI, not an agent listener. The installed tray
	// experience will own its own lifecycle; this preview exits after 15 minutes.
	<-time.After(15 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func servePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(page))
}

func serveStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(collect())
}

func collect() screenModel {
	observation, err := probe.Collect()
	if err != nil {
		observation = posture.Observation{}
	}
	report := posture.Evaluate(observation, runtime.GOOS, runtime.GOOS, version, time.Now())
	signals := []struct {
		label  string
		signal posture.Signal
	}{
		{"Disk encryption", report.DiskEncryption}, {"Screen lock", report.ScreenLock},
		{"Automatic updates", report.AutomaticUpdates}, {"Pending updates", report.PendingMaintenance},
		{"Endpoint protection", report.EndpointProtection},
	}
	model := screenModel{Title: "Your device, in view.", Description: "A private, read-only check of the security settings that protect your work.", CheckedAt: "Checked on this device · " + report.CollectedAt.Local().Format("Jan 2, 2006 at 3:04 PM")}
	for _, item := range signals {
		model.Rows = append(model.Rows, screenRow{Label: item.label, Value: displaySignal(item.signal), Status: string(item.signal.Status)})
	}
	return model
}

func displaySignal(signal posture.Signal) string {
	switch signal.Status {
	case posture.Pass:
		return "Protected"
	case posture.NeedsAttention:
		return "Review needed · updates are pending"
	case posture.Fail:
		return "Review needed · " + strings.ReplaceAll(signal.Code, "_", " ")
	default:
		return "Not available on this device"
	}
}

const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>HackZero Device Checker</title><style>
*{box-sizing:border-box}body{margin:0;background:#f7f5f1;color:#171717;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:930px;margin:0 auto;padding:45px 32px 64px}.brand{font-size:12px;font-weight:750;letter-spacing:.08em}.brand i{display:inline-block;width:7px;height:7px;background:#2785d7;border-radius:100%;margin-left:8px}.top{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #ded9d0;padding-bottom:28px}.pill{font-size:11px;letter-spacing:.08em;color:#27683b;background:#e9f4ec;border:1px solid #bedac6;border-radius:30px;padding:8px 12px}h1{font-family:Georgia,serif;font-size:clamp(44px,8vw,76px);font-weight:400;letter-spacing:-.06em;line-height:.92;margin:68px 0 20px;max-width:720px}h1 em{font-weight:400}.lede{font-size:18px;line-height:1.55;color:#58534f;max-width:610px}.panel{margin-top:43px;border:1px solid #ded9d0;background:#fffdfb;padding:20px}.row{display:flex;gap:18px;justify-content:space-between;align-items:center;background:#f4f1ed;margin:9px 0;padding:20px;border-left:3px solid #9b928a}.row.pass{background:#f2f7f3;border-color:#5a9b68}.row.fail,.row.needs_attention{background:#fff1ef;border-color:#d45c4d}.name{font-size:16px;font-weight:700}.value{font-size:14px;text-align:right;color:#756d67}.pass .value{color:#27683b}.fail .value,.needs_attention .value{color:#b13e32}.foot{display:flex;justify-content:space-between;align-items:center;gap:18px;padding-top:22px;color:#77716c;font-size:13px}button{border:1px solid #171717;background:#171717;color:white;padding:12px 18px;border-radius:2px;font:600 14px inherit;cursor:pointer}button:disabled{opacity:.6}.note{margin-top:26px;font-size:13px;line-height:1.5;color:#756d67}@media(max-width:600px){main{padding:30px 18px}.foot,.row{align-items:flex-start;flex-direction:column}.value{text-align:left}h1{margin-top:48px}}
</style></head><body><main><header class="top"><div class="brand">HACKZERO<i></i></div><div class="pill">READ-ONLY · LOCAL CHECK</div></header><h1 id="title">Your device,<br><em>in view.</em></h1><p class="lede" id="description"></p><section class="panel" id="checks" aria-live="polite"></section><div class="foot"><span id="checked">Checking this device…</span><button id="refresh" type="button">Check again</button></div><p class="note">Nothing on this page is sent anywhere. Connecting this device is a separate, explicit step.</p></main><script>const e=s=>document.querySelector(s);async function refresh(){let b=e('#refresh');b.disabled=true;b.textContent='Checking…';try{let d=await (await fetch('/api/status',{cache:'no-store'})).json();e('#title').innerHTML=d.title.replace(',',' ,<br>').replace('in view.','<em>in view.</em>');e('#description').textContent=d.description;e('#checked').textContent=d.checkedAt;e('#checks').innerHTML=d.rows.map(x=>'<div class="row '+x.status+'"><span class="name">'+x.label+'</span><span class="value">'+x.value+'</span></div>').join('')}catch(_){e('#checked').textContent='Could not check this device. Try again.'}finally{b.disabled=false;b.textContent='Check again'}}e('#refresh').onclick=refresh;refresh()</script></body></html>`

#!/usr/bin/env python3
"""
xss_tool_dark.py - modified version with live status panel and sparkline graph

Added top-right panel that shows:
 - Status: Active / Loaded
 - Completed requests
 - Errors
 - Avg latency (ms)
 - Throughput (req/s)
 - Active / Max concurrency
 - Sparkline graph showing latency history

Based on original file uploaded by user. Kept original behavior otherwise.
"""

from __future__ import annotations
import threading
import traceback
import queue
import csv
import sys
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

STOP_EVENT = threading.Event()

# ---------- Core logic (embedded) ----------

def read_lines_file(path: str) -> list[str]:
    out = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            out.append(s)
    return out

def inject_payload_into_param(url: str, param_name: str, payload: str) -> str:
    parsed = urlparse(url)
    query_list = parse_qsl(parsed.query, keep_blank_values=True)
    new_query = []
    replaced = False
    for (k, v) in query_list:
        if k == param_name and not replaced:
            new_query.append((k, payload))
            replaced = True
        else:
            new_query.append((k, v))
    if not replaced:
        new_query.append((param_name, payload))
    new_qs = urlencode(new_query, doseq=True, safe='/:?&=')
    parts = list(parsed)
    parts[4] = new_qs
    return urlunparse(parts)

def extract_params(url: str) -> list[str]:
    parsed = urlparse(url)
    query_list = parse_qsl(parsed.query, keep_blank_values=True)
    return [k for (k, _) in query_list]

def check_url_with_timeout(url: str, timeout: float, verify_tls: bool = True):
    """
    Returns (url, status, info, latency_seconds)
    """
    start = time.monotonic()
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=verify_tls)
        snippet = resp.text[:300].replace('\n', ' ')
        latency = max(0.0, time.monotonic() - start)
        return (url, resp.status_code, snippet, latency)
    except requests.exceptions.Timeout:
        latency = max(0.0, time.monotonic() - start)
        return (url, "TIMEOUT", None, latency)
    except requests.exceptions.RequestException as e:
        latency = max(0.0, time.monotonic() - start)
        return (url, "ERROR", str(e), latency)
    except Exception as e:
        latency = max(0.0, time.monotonic() - start)
        return (url, "ERROR", str(e), latency)

# ---------- Data holder ----------

class InjectedRow:
    def __init__(self, original: str, param: str, payload: str, injected: str):
        self.original = original
        self.param = param
        self.payload = payload
        self.injected = injected
        self.status: str | None = None
        self.info: str | None = None

# ---------- Worker thread (modified to send stats) ----------

def worker(cfg: dict, progress_cb, log_cb, finished_cb, stats_cb=None):
    """
    stats_cb is a callback(stats_dict) invoked periodically with:
    {
      'status': 'active'|'loaded',
      'completed': int,
      'errors': int,
      'avg_latency_ms': float,
      'throughput_rps': float,
      'active_workers': int,
      'max_concurrency': int
    }
    """
    try:
        log_cb("[*] Reading URL list …")
        urls = []
        if cfg['url_file']:
            urls = read_lines_file(cfg['url_file'])
        if not urls:
            log_cb("[!] No URLs provided.")
            finished_cb([])
            return

        payloads: list[str] = []
        if cfg.get('payload_file'):
            payloads.extend(read_lines_file(cfg['payload_file']))
        if cfg.get('inline_payloads'):
            payloads.extend([p for p in cfg['inline_payloads'] if p.strip() != ""])
        if not payloads:
            log_cb("[!] No payloads provided.")
            finished_cb([])
            return

        log_cb("[*] Injecting payloads …")
        injected_rows: list[InjectedRow] = []
        for url in urls:
            if STOP_EVENT.is_set():
                log_cb("[*] Stop requested.")
                finished_cb([])
                return
            params = extract_params(url)
            if cfg.get('verbose'):
                log_cb(f"[v] {url} → params {params}")
            if not params:
                continue
            for payload in payloads:
                for param in params:
                    inj = inject_payload_into_param(url, param, payload)
                    injected_rows.append(InjectedRow(original=url, param=param, payload=payload, injected=inj))

        log_cb(f"[+] Generated {len(injected_rows)} injected URLs.")
        # Optionally write to output
        if cfg.get('output_file'):
            try:
                mode = 'a' if cfg.get('append') else 'w'
                with open(cfg['output_file'], mode, encoding='utf-8') as fh:
                    for r in injected_rows:
                        fh.write(r.injected + "\n")
                log_cb(f"[+] Wrote injected URLs to {cfg['output_file']}")
            except Exception as e:
                log_cb(f"[!] Failed writing output: {e}")

        # If no live check requested, finish (status should be Loaded)
        if cfg.get('timeout') is None:
            if stats_cb:
                stats_cb({
                    'status': 'loaded',
                    'completed': 0,
                    'errors': 0,
                    'avg_latency_ms': 0.0,
                    'throughput_rps': 0.0,
                    'active_workers': 0,
                    'max_concurrency': int(cfg['concurrency']),
                })
            finished_cb(injected_rows)
            return

        # Live checks requested
        log_cb(f"[*] Performing live checks (timeout={cfg['timeout']}s) …")
        urls_to_check = [r.injected for r in injected_rows]
        total = len(urls_to_check)
        done = 0
        errors = 0
        latencies = []
        start_time = time.monotonic()
        max_conc = int(cfg['concurrency'])
        active_workers = 0
        active_workers_lock = threading.Lock()

        # wrapper around check to increment/decrement active_workers and push stats
        def wrapped_check(u):
            nonlocal active_workers, errors, done
            # increment
            with active_workers_lock:
                active_workers += 1
            if stats_cb:
                elapsed = time.monotonic() - start_time
                throughput = (done / elapsed) if elapsed > 0 else 0.0
                stats_cb({
                    'status': 'active',
                    'completed': done,
                    'errors': errors,
                    'avg_latency_ms': (sum(latencies)/len(latencies)*1000.0) if latencies else 0.0,
                    'throughput_rps': throughput,
                    'active_workers': active_workers,
                    'max_concurrency': max_conc,
                })
            try:
                u, status, info, latency = check_url_with_timeout(u, cfg['timeout'], cfg['verify_tls'])
                return (u, status, info, latency)
            finally:
                # decrement happens in the main loop after result processed
                pass

        with ThreadPoolExecutor(max_workers=max_conc) as ex:
            futures = {ex.submit(wrapped_check, u): u for u in urls_to_check}
            # iterate as completed so we can update GUI
            for fut in as_completed(futures):
                if STOP_EVENT.is_set():
                    log_cb("[*] Stopping checks …")
                    break
                url_checked = futures[fut]
                try:
                    u, status, info, latency = fut.result()
                except Exception as e:
                    u = url_checked
                    status = "ERROR"
                    info = str(e)
                    latency = 0.0
                # map to injected_rows
                for r in injected_rows:
                    if r.injected == u and r.status is None:
                        r.status = str(status)
                        r.info = info or ""
                        break
                # update counters
                done += 1
                if str(status).upper() != "200":
                    # Treat non-200 as an error for counting purposes (you can adjust here)
                    if str(status).upper() in ("ERROR", "TIMEOUT"):
                        errors += 1
                if latency:
                    latencies.append(latency)
                # after processing, decrement active_workers
                with active_workers_lock:
                    active_workers = max(0, active_workers - 1)

                # compute stats
                elapsed = time.monotonic() - start_time
                avg_lat_ms = (sum(latencies)/len(latencies)*1000.0) if latencies else 0.0
                throughput = (done / elapsed) if elapsed > 0 else 0.0
                if stats_cb:
                    stats_cb({
                        'status': 'active',
                        'completed': done,
                        'errors': errors,
                        'avg_latency_ms': avg_lat_ms,
                        'throughput_rps': throughput,
                        'active_workers': active_workers,
                        'max_concurrency': max_conc,
                    })

                progress = int((done / total) * 100)
                progress_cb(progress)

        log_cb("[+] Live checks done.")
        progress_cb(100)
        # final status -> loaded (not active)
        if stats_cb:
            elapsed = time.monotonic() - start_time
            final_throughput = (done / elapsed) if elapsed > 0 else 0.0
            stats_cb({
                'status': 'loaded',
                'completed': done,
                'errors': errors,
                'avg_latency_ms': (sum(latencies)/len(latencies)*1000.0) if latencies else 0.0,
                'throughput_rps': final_throughput,
                'active_workers': 0,
                'max_concurrency': max_conc,
            })
        finished_cb(injected_rows)
    except Exception as e:
        tb = traceback.format_exc()
        log_cb(f"[!] Worker exception: {e}\n{tb}")
        finished_cb([])

# ---------- GUI (dark theme) ----------

class DarkStyle(ttk.Style):
    def __init__(self):
        super().__init__()
        self.setup_dark()

    def setup_dark(self):
        try:
            self.theme_use('clam')
        except Exception:
            pass
        bg = '#222222'
        fg = '#eeeeee'
        entry_bg = '#333333'
        text_bg = '#1e1e1e'
        btn_bg = '#444444'
        btn_fg = '#ffffff'
        sel_bg = '#555555'
        sel_fg = '#ffffff'

        self.configure('.', background=bg, foreground=fg, fieldbackground=entry_bg)
        self.configure('TLabel', background=bg, foreground=fg)
        self.configure('TFrame', background=bg)
        self.configure('TEntry', foreground=fg, fieldbackground=entry_bg)
        self.configure('TButton', background=btn_bg, foreground=btn_fg)
        self.configure('TCheckbutton', background=bg, foreground=fg)
        self.configure('TSpinbox', fieldbackground=entry_bg, foreground=fg)
        self.configure('Treeview', background=text_bg, foreground=fg, fieldbackground=text_bg)
        self.configure('Treeview.Heading', background=btn_bg, foreground=fg)

        self.map('Treeview', background=[('selected', sel_bg)], foreground=[('selected', sel_fg)])
        self.map('TButton', background=[('active', '#555555')])
        self.map('TEntry', fieldbackground=[('!disabled', entry_bg)], foreground=[('!disabled', fg)])
        self.map('TSpinbox', fieldbackground=[('!disabled', entry_bg)], foreground=[('!disabled', fg)])

class XSSDarkGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("OUT-OF-BAND Vulnerability tester - Devoloped by Mishal e — self-contained")
        self.geometry("1100x720")
        self.style = DarkStyle()
        self.configure(background='#222222')
        
        # Initialize sparkline data
        self.spark_samples = []
        self.spark_max_samples = 100
        self.spark_min_ms = 0.0
        self.spark_max_ms = 2000.0  # initial scale
        
        self._build_ui()
        self.current_results: list[InjectedRow] = None
        self.worker_thread: threading.Thread | None = None

        # metrics state
        self._metrics = {
            'status': 'loaded',
            'completed': 0,
            'errors': 0,
            'avg_latency_ms': 0.0,
            'throughput_rps': 0.0,
            'active_workers': 0,
            'max_concurrency': 0
        }

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill='both', expand=True)

        # top row contains inputs on the left and metrics panel on the right
        top = ttk.Frame(frm)
        top.pack(fill='x', pady=(0,8))

        left_top = ttk.Frame(top)
        left_top.pack(side='left', fill='x', expand=True)

        ttk.Label(left_top, text="URL list file:").grid(row=0, column=0, sticky='w')
        self.url_entry = ttk.Entry(left_top, width=70)
        self.url_entry.grid(row=0, column=1, sticky='we', padx=5)
        ttk.Button(left_top, text="Browse…", command=self.browse_url).grid(row=0, column=2)

        ttk.Label(left_top, text="Payload file (optional):").grid(row=1, column=0, sticky='w')
        self.payload_entry = ttk.Entry(left_top, width=70)
        self.payload_entry.grid(row=1, column=1, sticky='we', padx=5)
        ttk.Button(left_top, text="Browse…", command=self.browse_payload).grid(row=1, column=2)

        ttk.Label(left_top, text="Output file (optional):").grid(row=2, column=0, sticky='w')
        self.output_entry = ttk.Entry(left_top, width=70)
        self.output_entry.grid(row=2, column=1, sticky='we', padx=5)
        ttk.Button(left_top, text="Save to…", command=self.browse_output).grid(row=2, column=2)

        # metrics panel on the right (top-right)
        metrics_frame = ttk.Frame(top)
        metrics_frame.pack(side='right', fill='y', padx=(8,0))
        metrics_label = ttk.Label(metrics_frame, text="Status (Live)", font=("TkDefaultFont", 10, "bold"))
        metrics_label.pack(anchor='e', pady=(0,6))

        # status badge
        self.status_var = tk.StringVar(value="Loaded")
        self.status_badge = ttk.Label(metrics_frame, textvariable=self.status_var, relief='ridge', padding=(6,4))
        self.status_badge.pack(anchor='e', pady=(0,6))
        
        # sparkline canvas (small) - ADDED FROM PRO.PY
        self.spark_canvas = tk.Canvas(metrics_frame, width=220, height=48, highlightthickness=0, bd=0, bg='#222222')
        self.spark_canvas.pack(anchor='e', pady=(0,6))

        # metrics lines
        self.completed_var = tk.StringVar(value="Completed: 0")
        ttk.Label(metrics_frame, textvariable=self.completed_var).pack(anchor='e')
        self.errors_var = tk.StringVar(value="Errors: 0")
        ttk.Label(metrics_frame, textvariable=self.errors_var).pack(anchor='e')
        self.avglat_var = tk.StringVar(value="Avg latency: 0 ms")
        ttk.Label(metrics_frame, textvariable=self.avglat_var).pack(anchor='e')
        self.throughput_var = tk.StringVar(value="Throughput: 0 req/s")
        ttk.Label(metrics_frame, textvariable=self.throughput_var).pack(anchor='e')
        self.conc_var = tk.StringVar(value="Active/Max: 0/0")
        ttk.Label(metrics_frame, textvariable=self.conc_var).pack(anchor='e')

        # Inline payloads
        ttk.Label(frm, text="Inline payloads (one per line):").pack(anchor='w')
        self.inline_txt = tk.Text(frm, height=6, bg='#1e1e1e', fg='#eeeeee', insertbackground='#ffffff')
        self.inline_txt.pack(fill='x', pady=(0,6))

        opts = ttk.Frame(frm)
        opts.pack(fill='x', pady=(0,8))
        ttk.Label(opts, text="Timeout (s, 0=no live checks):").grid(row=0, column=0, sticky='w')
        self.timeout_var = tk.DoubleVar(value=5.0)
        self.timeout_spin = ttk.Spinbox(opts, from_=0.0, to=120.0, increment=0.5, textvariable=self.timeout_var, width=8)
        self.timeout_spin.grid(row=0, column=1, sticky='w', padx=6)

        ttk.Label(opts, text="Concurrency:").grid(row=0, column=2, sticky='w', padx=(12,0))
        self.concurrency_var = tk.IntVar(value=10)
        self.concurrency_spin = ttk.Spinbox(opts, from_=1, to=200, textvariable=self.concurrency_var, width=6)
        self.concurrency_spin.grid(row=0, column=3, sticky='w', padx=6)

        self.verify_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Verify TLS", variable=self.verify_var).grid(row=0, column=4, padx=(12,0))
        self.append_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Append output", variable=self.append_var).grid(row=0, column=5, padx=(12,0))
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Verbose (log)", variable=self.verbose_var).grid(row=0, column=6, padx=(12,0))

        btns = ttk.Frame(frm)
        btns.pack(fill='x', pady=(0,8))
        self.start_btn = ttk.Button(btns, text="Start", command=self.start)
        self.start_btn.pack(side='left')
        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop, state='disabled')
        self.stop_btn.pack(side='left', padx=(6,0))
        self.export_btn = ttk.Button(btns, text="Export CSV", command=self.export_csv, state='disabled')
        self.export_btn.pack(side='right')

        prlog = ttk.Frame(frm)
        prlog.pack(fill='both', expand=False)
        self.progress = ttk.Progressbar(prlog, orient='horizontal', mode='determinate')
        self.progress.pack(fill='x', pady=(6,4))
        self.log_txt = tk.Text(prlog, height=8, bg='#1e1e1e', fg='#eeeeee', insertbackground='#ffffff', state='disabled')
        self.log_txt.pack(fill='x')

        split = ttk.PanedWindow(frm, orient='vertical')
        split.pack(fill='both', expand=True, pady=(8,0))

        preview_frame = ttk.Labelframe(split, text="Preview (by payload)")
        self.preview_tree = ttk.Treeview(preview_frame, columns=('orig','param','payload','inj'), show='headings')
        for col, name in [('orig','Original'), ('param','Param'), ('payload','Payload'), ('inj','Injected URL')]:
            self.preview_tree.heading(col, text=name)
        self.preview_tree.column('orig', width=260)
        self.preview_tree.column('param', width=80, anchor='center')
        self.preview_tree.column('payload', width=220)
        self.preview_tree.column('inj', width=420)
        self.preview_tree.pack(fill='both', expand=True)
        preview_frame.pack(fill='both', expand=True)
        split.add(preview_frame)

        results_frame = ttk.Labelframe(split, text="Results")
        self.results_tree = ttk.Treeview(results_frame, columns=('status','orig','param','payload','inj'), show='headings')
        for col, name in [('status','Status'), ('orig','Original'), ('param','Param'), ('payload','Payload'), ('inj','Injected URL')]:
            self.results_tree.heading(col, text=name)
        self.results_tree.column('status', width=90, anchor='center')
        self.results_tree.column('orig', width=220)
        self.results_tree.column('param', width=80, anchor='center')
        self.results_tree.column('payload', width=220)
        self.results_tree.column('inj', width=420)
        self.results_tree.pack(fill='both', expand=True)
        results_frame.pack(fill='both', expand=True)
        split.add(results_frame)

        footer = ttk.Label(frm, text="Only use on authorized targets.", foreground='#ff6666', background='#222222')
        footer.pack(anchor='w', pady=(6,0))
        
        # Initial sparkline draw
        self._draw_sparkline()

    # UI helpers
    def browse_url(self):
        f = filedialog.askopenfilename(title="Select URL file", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if f:
            self.url_entry.delete(0, tk.END); self.url_entry.insert(0, f)

    def browse_payload(self):
        f = filedialog.askopenfilename(title="Select payload file", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if f:
            self.payload_entry.delete(0, tk.END); self.payload_entry.insert(0, f)

    def browse_output(self):
        f = filedialog.asksaveasfilename(title="Save output", defaultextension=".txt", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if f:
            self.output_entry.delete(0, tk.END); self.output_entry.insert(0, f)

    def log(self, s: str):
        self.log_txt.configure(state='normal')
        self.log_txt.insert('end', s + "\n")
        self.log_txt.see('end')
        self.log_txt.configure(state='disabled')

    # Sparkline drawing function - ADDED FROM PRO.PY
    def _draw_sparkline(self):
        # guard in case called too early
        if not hasattr(self, "spark_canvas") or not hasattr(self, "spark_samples"):
            return
        c = self.spark_canvas
        c.delete('all')
        try:
            w = int(c['width'])
            h = int(c['height'])
        except Exception:
            w, h = 220, 48
        samples = self.spark_samples
        if not samples:
            # draw baseline
            c.create_line(2, h-6, w-2, h-6, fill="#333333")
            return
        # scale samples to fit
        mn = self.spark_min_ms
        mx = max(self.spark_max_ms, mn + 1.0)
        rng = mx - mn
        pts = []
        n = len(samples)
        for i, s in enumerate(samples):
            x = 4 + (w-8) * (i / max(1, n-1))
            # invert y because canvas origin is top-left
            y = 4 + (h-8) * (1.0 - (s - mn) / rng)
            pts.append((x, y))
        # draw area fill (subtle)
        area_points = []
        for (x,y) in pts:
            area_points.extend((x,y))
        # close area to baseline
        area_points.extend((w-4, h-4, 4, h-4))
        try:
            c.create_polygon(area_points, fill='#1c1c1c', outline='')
        except Exception:
            pass
        # draw line
        flat = []
        for (x,y) in pts:
            flat.extend((x,y))
        c.create_line(flat, fill='#5cc1ff', width=2.0, smooth=True)
        # draw endpoint dot
        if pts:
            ex, ey = pts[-1]
            c.create_oval(ex-3, ey-3, ex+3, ey+3, fill='#3d6ea7', outline='')

    # metrics update (called on main thread via after)
    def _apply_metrics(self, metrics: dict):
        self._metrics.update(metrics)
        st = metrics.get('status', self._metrics['status'])
        # status label text
        txt = "Active" if st == 'active' else "Loaded"
        self.status_var.set(txt)
        # Completed / Errors
        self.completed_var.set(f"Completed: {self._metrics.get('completed',0)}")
        self.errors_var.set(f"Errors: {self._metrics.get('errors',0)}")
        # avg latency ms
        avgms = float(self._metrics.get('avg_latency_ms', 0.0))
        self.avglat_var.set(f"Avg latency: {avgms:.1f} ms")
        # throughput
        self.throughput_var.set(f"Throughput: {self._metrics.get('throughput_rps',0.0):.2f} req/s")
        # active/max conc
        aw = int(self._metrics.get('active_workers', 0))
        mc = int(self._metrics.get('max_concurrency', 0))
        self.conc_var.set(f"Active/Max: {aw}/{mc}")

        # update sparkline samples list if avg latency present (append the sample in ms) - ADDED FROM PRO.PY
        try:
            if metrics.get('avg_latency_ms') is not None:
                sample = float(metrics.get('avg_latency_ms', 0.0))
                # keep ms samples (already ms)
                self.spark_samples.append(sample)
                if len(self.spark_samples) > self.spark_max_samples:
                    self.spark_samples = self.spark_samples[-self.spark_max_samples:]
                # update the dynamic min/max for scaling (with margins)
                if self.spark_samples:
                    cur_min = min(self.spark_samples)
                    cur_max = max(self.spark_samples)
                    # avoid zero-range
                    span = max(1.0, cur_max - cur_min)
                    self.spark_min_ms = max(0.0, cur_min - 0.05 * span)
                    self.spark_max_ms = cur_max + 0.05 * span
                self._draw_sparkline()
        except Exception:
            pass

    def start(self):
        url_file = self.url_entry.get().strip()
        if not url_file:
            messagebox.showwarning("Missing URL file", "Please select a URL list file.")
            return
        payload_file = self.payload_entry.get().strip() or None
        output_file = self.output_entry.get().strip() or None
        inline = [l for l in self.inline_txt.get("1.0","end").splitlines() if l.strip() != ""]
        tval = float(self.timeout_var.get())
        timeout = tval if tval > 0 else None

        cfg = {
            'url_file': url_file,
            'payload_file': payload_file,
            'inline_payloads': inline,
            'timeout': timeout,
            'concurrency': int(self.concurrency_var.get()),
            'verify_tls': bool(self.verify_var.get()),
            'append': bool(self.append_var.get()),
            'output_file': output_file,
            'verbose': bool(self.verbose_var.get()),
        }

        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.export_btn.config(state='disabled')
        self.progress['value'] = 0
        self.log_txt.configure(state='normal')
        self.log_txt.delete('1.0','end')
        self.log_txt.configure(state='disabled')
        self.preview_tree.delete(*self.preview_tree.get_children())
        self.results_tree.delete(*self.results_tree.get_children())
        STOP_EVENT.clear()

        # reset sparkline samples on start - ADDED FROM PRO.PY
        self.spark_samples = []

        def prog_cb(p):
            try:
                self.progress['value'] = int(p)
            except:
                pass

        def log_cb(msg):
            self.after(0, lambda: self.log(msg))

        def stats_cb(metrics: dict):
            # schedule on main thread
            self.after(0, lambda: self._apply_metrics(metrics))

        def fin_cb(results: list[InjectedRow]):
            def finalize():
                self.worker_thread = None
                self.start_btn.config(state='normal')
                self.stop_btn.config(state='disabled')
                self.export_btn.config(state='normal' if results else 'disabled')
                self.current_results = results

                # preview
                self.preview_tree.delete(*self.preview_tree.get_children())
                byp = {}
                for r in results:
                    byp.setdefault(r.payload, []).append(r)
                for payload, rows in byp.items():
                    parent = self.preview_tree.insert('', 'end', values=("", "", payload, ""))
                    for rr in rows:
                        self.preview_tree.insert(parent, 'end', values=(rr.original, rr.param, rr.payload, rr.injected))

                # results
                self.results_tree.delete(*self.results_tree.get_children())
                for r in results:
                    st = r.status or ""
                    self.results_tree.insert('', 'end', values=(st, r.original, r.param, r.payload, r.injected))

                self.progress['value'] = 100
                self.log("[*] Finished.")

                # Final metrics set to loaded if not already
                self.after(0, lambda: self._apply_metrics({'status': 'loaded'}))
            self.after(0, finalize)

        th = threading.Thread(target=worker, args=(cfg, prog_cb, log_cb, fin_cb, stats_cb), daemon=True)
        self.worker_thread = th
        th.start()
        self.log("[*] Worker started.")
        # set initial metric state (active if live checks requested)
        if cfg.get('timeout') is not None:
            self._apply_metrics({'status': 'active', 'max_concurrency': cfg['concurrency']})
        else:
            self._apply_metrics({'status': 'loaded', 'max_concurrency': cfg['concurrency']})

    def stop(self):
        if messagebox.askyesno("Stop", "Stop current run?"):
            STOP_EVENT.set()
            self.log("[*] Stop requested.")
            self.stop_btn.config(state='disabled')

    def export_csv(self):
        if not self.current_results:
            messagebox.showinfo("No results", "Nothing to export.")
            return
        f = filedialog.asksaveasfilename(title="Export CSV", defaultextension=".csv", filetypes=[("CSV","*.csv"),("All files","*.*")])
        if not f:
            return
        try:
            with open(f, 'w', newline='', encoding='utf-8') as fh:
                writer = csv.writer(fh)
                writer.writerow(["Status","Original","Param","Payload","InjectedURL","Info"])
                for r in self.current_results:
                    writer.writerow([r.status or "", r.original, r.param, r.payload, r.injected, r.info or ""])
            self.log(f"[+] Exported results to {f}")
            messagebox.showinfo("Exported", f"Results exported to {f}")
        except Exception as e:
            self.log(f"[!] Export failed: {e}")
            messagebox.showerror("Error", f"Failed export: {e}")

def main():
    app = XSSDarkGUI()
    app.mainloop()

if __name__ == '__main__':
    main()

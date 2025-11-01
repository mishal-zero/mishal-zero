#!/usr/bin/env python3
"""
xss_tool_dark.py

Standalone GUI tool (dark themed) for XSS URL injection + optional live check.

Usage:
    python3 xss_tool_dark.py

Dependencies:
    - Python 3 with tkinter (standard)
    - requests (for live checks): `pip3 install requests`
"""

from __future__ import annotations
import threading
import traceback
import queue
import csv
import sys
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
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=verify_tls)
        snippet = resp.text[:300].replace('\n', ' ')
        return (url, resp.status_code, snippet)
    except requests.exceptions.Timeout:
        return (url, "TIMEOUT", None)
    except requests.exceptions.RequestException as e:
        return (url, "ERROR", str(e))
    except Exception as e:
        return (url, "ERROR", str(e))

# ---------- Data holder ----------

class InjectedRow:
    def __init__(self, original: str, param: str, payload: str, injected: str):
        self.original = original
        self.param = param
        self.payload = payload
        self.injected = injected
        self.status: str | None = None
        self.info: str | None = None

# ---------- Worker thread ----------

def worker(cfg: dict, progress_cb, log_cb, finished_cb):
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

        # If no live check requested, finish
        if cfg.get('timeout') is None:
            finished_cb(injected_rows)
            return

        log_cb(f"[*] Performing live checks (timeout={cfg['timeout']}s) …")
        urls_to_check = [r.injected for r in injected_rows]
        total = len(urls_to_check)
        done = 0

        with ThreadPoolExecutor(max_workers=cfg['concurrency']) as ex:
            futures = {ex.submit(check_url_with_timeout, u, cfg['timeout'], cfg['verify_tls']): u for u in urls_to_check}
            for fut in as_completed(futures):
                if STOP_EVENT.is_set():
                    log_cb("[*] Stopping checks …")
                    break
                url_checked = futures[fut]
                try:
                    u, status, info = fut.result()
                except Exception as e:
                    u = url_checked
                    status = "ERROR"
                    info = str(e)
                # map to injected_rows
                for r in injected_rows:
                    if r.injected == u and r.status is None:
                        r.status = str(status)
                        r.info = info or ""
                        break
                done += 1
                progress = int((done / total) * 100)
                progress_cb(progress)
        log_cb("[+] Live checks done.")
        progress_cb(100)
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
        self.title("OUT-OF-BAND Vulnerability tester - Devoloped by Mishal e — self‑contained")
        self.geometry("1100x720")
        self.style = DarkStyle()
        self.configure(background='#222222')
        self._build_ui()
        self.current_results: list[InjectedRow] = None
        self.worker_thread: threading.Thread | None = None

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill='both', expand=True)

        top = ttk.Frame(frm)
        top.pack(fill='x', pady=(0,8))

        ttk.Label(top, text="URL list file:").grid(row=0, column=0, sticky='w')
        self.url_entry = ttk.Entry(top, width=70)
        self.url_entry.grid(row=0, column=1, sticky='we', padx=5)
        ttk.Button(top, text="Browse…", command=self.browse_url).grid(row=0, column=2)

        ttk.Label(top, text="Payload file (optional):").grid(row=1, column=0, sticky='w')
        self.payload_entry = ttk.Entry(top, width=70)
        self.payload_entry.grid(row=1, column=1, sticky='we', padx=5)
        ttk.Button(top, text="Browse…", command=self.browse_payload).grid(row=1, column=2)

        ttk.Label(top, text="Output file (optional):").grid(row=2, column=0, sticky='w')
        self.output_entry = ttk.Entry(top, width=70)
        self.output_entry.grid(row=2, column=1, sticky='we', padx=5)
        ttk.Button(top, text="Save to…", command=self.browse_output).grid(row=2, column=2)

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

        def prog_cb(p):
            try:
                self.progress['value'] = int(p)
            except:
                pass

        def log_cb(msg):
            self.after(0, lambda: self.log(msg))

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
            self.after(0, finalize)

        th = threading.Thread(target=worker, args=(cfg, prog_cb, log_cb, fin_cb), daemon=True)
        self.worker_thread = th
        th.start()
        self.log("[*] Worker started.")

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


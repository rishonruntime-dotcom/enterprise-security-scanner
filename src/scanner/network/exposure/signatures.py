"""
Service fingerprint database for network exposure analysis.

Maps port/service signatures to known products, versions, vendors, and risk profiles.
Includes Edge Infrastructure signatures (CDN, Reverse Proxy, WAF, Load Balancer).
"""
from typing import Dict, List, Optional, Any


SERVICE_SIGNATURES: Dict[int, Dict[str, Any]] = {
    # File Transfer
    20: {"service": "FTP Data", "product": "FTP Data", "vendor": "Generic", "category": "File Sharing", "risk": "Info"},
    21: {"service": "FTP", "product": "FTP", "vendor": "Generic", "category": "File Sharing", "risk": "High", "default_creds": True, "anonymous_auth": True, "references": ["CWE-288", "CAPEC-115"]},
    69: {"service": "TFTP", "product": "TFTP", "vendor": "Generic", "category": "File Sharing", "risk": "Critical", "references": ["CWE-319"]},
    873: {"service": "rsync", "product": "rsync", "vendor": "Open Source", "category": "File Sharing", "risk": "High"},
    989: {"service": "FTPS Data", "product": "FTPS Data", "vendor": "Generic", "category": "File Sharing", "risk": "Low"},
    990: {"service": "FTPS", "product": "FTPS", "vendor": "Generic", "category": "File Sharing", "risk": "Low"},
    2049: {"service": "NFS", "product": "NFS", "vendor": "Generic", "category": "File Sharing", "risk": "High"},
    139: {"service": "NetBIOS-SSN", "product": "NetBIOS", "vendor": "Microsoft", "category": "File Sharing", "risk": "High"},
    445: {"service": "SMB", "product": "SMB / CIFS", "vendor": "Microsoft", "category": "File Sharing", "risk": "Critical", "default_creds": True, "references": ["CWE-120", "CAPEC-233"]},

    # Remote Access
    22: {"service": "SSH", "product": "OpenSSH", "vendor": "OpenBSD", "category": "Remote Administration", "risk": "Info", "default_creds": False, "references": ["CWE-308"]},
    23: {"service": "Telnet", "product": "Telnet", "vendor": "Generic", "category": "Remote Administration", "risk": "Critical", "default_creds": False, "references": ["CWE-319", "CAPEC-157"]},
    3389: {"service": "RDP", "product": "Remote Desktop Protocol", "vendor": "Microsoft", "category": "Remote Administration", "risk": "Critical", "default_creds": True, "references": ["CWE-288", "CAPEC-115"]},
    5900: {"service": "VNC", "product": "VNC Server", "vendor": "RealVNC / Generic", "category": "Remote Administration", "risk": "Critical", "default_creds": True, "references": ["CWE-288", "CAPEC-115"]},
    5985: {"service": "WinRM HTTP", "product": "Windows Remote Management", "vendor": "Microsoft", "category": "Remote Administration", "risk": "Medium"},
    5986: {"service": "WinRM HTTPS", "product": "Windows Remote Management TLS", "vendor": "Microsoft", "category": "Remote Administration", "risk": "Low"},

    # Web
    80: {"service": "HTTP", "product": "HTTP Web Service", "vendor": "Generic", "category": "Web", "risk": "Info"},
    443: {"service": "HTTPS", "product": "HTTPS Web Service", "vendor": "Generic", "category": "Web", "risk": "Info"},
    8080: {"service": "HTTP Alternate", "product": "HTTP Proxy / Web App", "vendor": "Generic", "category": "Web", "risk": "Medium"},
    8081: {"service": "Alternate Web", "product": "Web Application Service", "vendor": "Generic", "category": "Web", "risk": "Medium"},
    8443: {"service": "HTTPS Alternate", "product": "HTTPS Admin / Web App", "vendor": "Generic", "category": "Web", "risk": "Medium"},

    # Databases
    1433: {"service": "MSSQL", "product": "Microsoft SQL Server", "vendor": "Microsoft", "category": "Database", "risk": "Critical", "default_creds": True, "references": ["CWE-89", "CAPEC-66"]},
    1521: {"service": "Oracle", "product": "Oracle Database TNS Listener", "vendor": "Oracle", "category": "Database", "risk": "Critical", "references": ["CWE-89"]},
    3306: {"service": "MySQL", "product": "MySQL Server", "vendor": "Oracle / MySQL", "category": "Database", "risk": "Critical", "default_creds": True, "references": ["CWE-89", "CAPEC-66"]},
    5432: {"service": "PostgreSQL", "product": "PostgreSQL Database", "vendor": "PostgreSQL Global Development Group", "category": "Database", "risk": "Critical", "default_creds": True, "references": ["CWE-89", "CAPEC-66"]},
    6379: {"service": "Redis", "product": "Redis In-Memory Store", "vendor": "Redis Ltd", "category": "Database", "risk": "Critical", "default_creds": True, "anonymous_auth": True, "references": ["CWE-306", "CAPEC-115"]},
    7199: {"service": "Cassandra JMX", "product": "Apache Cassandra JMX", "vendor": "Apache", "category": "Database", "risk": "High"},
    9200: {"service": "Elasticsearch", "product": "Elasticsearch REST API", "vendor": "Elastic", "category": "Database", "risk": "Critical", "anonymous_auth": True, "references": ["CWE-306", "CAPEC-115"]},
    9300: {"service": "Elasticsearch Cluster", "product": "Elasticsearch Transport", "vendor": "Elastic", "category": "Database", "risk": "High"},
    27017: {"service": "MongoDB", "product": "MongoDB Database", "vendor": "MongoDB Inc", "category": "Database", "risk": "Critical", "default_creds": True, "anonymous_auth": True, "references": ["CWE-306", "CAPEC-115"]},
    27018: {"service": "MongoDB Shard", "product": "MongoDB Sharding", "vendor": "MongoDB Inc", "category": "Database", "risk": "Critical"},

    # Email
    25: {"service": "SMTP", "product": "SMTP Mail Gateway", "vendor": "Generic", "category": "Email", "risk": "Medium"},
    110: {"service": "POP3", "product": "POP3 Mail Server", "vendor": "Generic", "category": "Email", "risk": "High"},
    143: {"service": "IMAP", "product": "IMAP Mail Server", "vendor": "Generic", "category": "Email", "risk": "Medium"},
    465: {"service": "SMTPS", "product": "SMTPS Mail Gateway", "vendor": "Generic", "category": "Email", "risk": "Low"},
    587: {"service": "SMTP Submission", "product": "SMTP Message Submission", "vendor": "Generic", "category": "Email", "risk": "Low"},
    993: {"service": "IMAPS", "product": "IMAPS Mail Server", "vendor": "Generic", "category": "Email", "risk": "Low"},
    995: {"service": "POP3S", "product": "POP3S Mail Server", "vendor": "Generic", "category": "Email", "risk": "Low"},

    # Infrastructure & Directory
    53: {"service": "DNS", "product": "Domain Name System", "vendor": "Generic", "category": "DNS", "risk": "Info"},
    67: {"service": "DHCP Server", "product": "DHCP Server", "vendor": "Generic", "category": "Infrastructure", "risk": "Info"},
    68: {"service": "DHCP Client", "product": "DHCP Client", "vendor": "Generic", "category": "Infrastructure", "risk": "Info"},
    123: {"service": "NTP", "product": "Network Time Protocol", "vendor": "Generic", "category": "Infrastructure", "risk": "Info"},
    135: {"service": "MS RPC", "product": "Microsoft RPC Endpoint Mapper", "vendor": "Microsoft", "category": "Infrastructure", "risk": "High"},
    137: {"service": "NetBIOS Name", "product": "NetBIOS Name Service", "vendor": "Microsoft", "category": "Infrastructure", "risk": "High"},
    138: {"service": "NetBIOS Datagram", "product": "NetBIOS Datagram Service", "vendor": "Microsoft", "category": "Infrastructure", "risk": "High"},
    161: {"service": "SNMP", "product": "Simple Network Management Protocol", "vendor": "Generic", "category": "Infrastructure", "risk": "High"},
    162: {"service": "SNMP Trap", "product": "SNMP Trap Receiver", "vendor": "Generic", "category": "Infrastructure", "risk": "High"},
    179: {"service": "BGP", "product": "Border Gateway Protocol", "vendor": "Generic", "category": "Infrastructure", "risk": "Medium"},
    389: {"service": "LDAP", "product": "Lightweight Directory Access Protocol", "vendor": "Generic / Microsoft", "category": "Infrastructure", "risk": "High"},
    636: {"service": "LDAPS", "product": "LDAP over TLS", "vendor": "Generic / Microsoft", "category": "Infrastructure", "risk": "Medium"},
    514: {"service": "Syslog", "product": "Syslog Receiver", "vendor": "Generic", "category": "Infrastructure", "risk": "Info"},
    631: {"service": "IPP Printer", "product": "Internet Printing Protocol", "vendor": "Generic", "category": "Printing", "risk": "Info"},

    # DevOps, Containers & Cloud
    1080: {"service": "SOCKS Proxy", "product": "SOCKS Proxy Server", "vendor": "Generic", "category": "Infrastructure", "risk": "High"},
    1883: {"service": "MQTT", "product": "MQTT Message Broker", "vendor": "Eclipse / Mosquitto", "category": "IoT", "risk": "Medium"},
    2375: {"service": "Docker API", "product": "Docker Engine Daemon Unauthenticated", "vendor": "Docker / Moby", "category": "Docker", "risk": "Critical", "references": ["CWE-306", "CAPEC-115"]},
    2376: {"service": "Docker TLS", "product": "Docker Engine Daemon TLS", "vendor": "Docker / Moby", "category": "Docker", "risk": "Medium"},
    2379: {"service": "etcd API", "product": "etcd Key-Value Store", "vendor": "CNCF", "category": "Kubernetes", "risk": "Critical"},
    2380: {"service": "etcd Peer", "product": "etcd Cluster Peer", "vendor": "CNCF", "category": "Kubernetes", "risk": "Critical"},
    4369: {"service": "Erlang Port Mapper", "product": "EPMD", "vendor": "Erlang / Open Telecom Platform", "category": "DevOps", "risk": "Medium"},
    5000: {"service": "Development Server", "product": "Python Flask / Docker Registry", "vendor": "Generic", "category": "DevOps", "risk": "Medium"},
    5601: {"service": "Kibana", "product": "Kibana Dashboard", "vendor": "Elastic", "category": "Monitoring", "risk": "High"},
    5672: {"service": "RabbitMQ", "product": "RabbitMQ AMQP Broker", "vendor": "VMware / RabbitMQ", "category": "Messaging", "risk": "Medium"},
    6443: {"service": "Kubernetes API", "product": "Kubernetes API Server", "vendor": "Kubernetes / CNCF", "category": "Kubernetes", "risk": "Critical"},
    7001: {"service": "WebLogic", "product": "Oracle WebLogic Server", "vendor": "Oracle", "category": "Web", "risk": "High"},
    9090: {"service": "Prometheus", "product": "Prometheus Metrics Server", "vendor": "Prometheus / CNCF", "category": "Monitoring", "risk": "High"},
    9418: {"service": "Git Protocol", "product": "Git Daemon", "vendor": "Git", "category": "DevOps", "risk": "Medium"},
    10000: {"service": "Webmin", "product": "Webmin Control Panel", "vendor": "Webmin", "category": "Remote Administration", "risk": "Critical"},
    11211: {"service": "Memcached", "product": "Memcached Key-Value Store", "vendor": "Memcached", "category": "Database", "risk": "Critical", "anonymous_auth": True},
    50000: {"service": "SAP Control", "product": "SAP NetWeaver Application Server", "vendor": "SAP", "category": "Infrastructure", "risk": "High"},
}

VENDOR_MAPPINGS: Dict[str, str] = {
    "nginx": "F5 / Nginx",
    "apache": "Apache Software Foundation",
    "openssh": "OpenBSD",
    "microsoft": "Microsoft Corporation",
    "mysql": "Oracle Corporation",
    "postgresql": "PostgreSQL Global Development Group",
    "redis": "Redis Ltd",
    "mongodb": "MongoDB Inc",
    "elasticsearch": "Elastic",
    "docker": "Docker Inc",
    "kubernetes": "CNCF / Kubernetes",
    "cloudflare": "Cloudflare Inc",
    "akamai": "Akamai Technologies",
    "fastly": "Fastly Inc",
    "oracle": "Oracle Corporation",
}

BANNER_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "SSH": {
        "pattern": r"SSH-([\d.]+)-([\w.-]+)",
        "version_group": 1,
        "product_group": 2,
        "vendor": "OpenBSD",
    },
    "FTP": {
        "pattern": r"(vsFTPd|ProFTPD|Pure-FTPd|FileZilla|wu-ftpd)\s*([\d.]+)?",
        "product_group": 1,
        "version_group": 2,
    },
    "SMTP": {
        "pattern": r"220 ([^\r\n]+) ESMTP",
        "product_group": 1,
    },
    "HTTP": {
        "pattern": r"Server:\s*([^\r\n]+)",
        "product_group": 1,
    },
    "MySQL": {
        "pattern": r"([\w.-]+)\s+\*?([\d.]+[\w.-]*)",
        "product_group": 1,
        "version_group": 2,
        "vendor": "Oracle Corporation",
    },
    "PostgreSQL": {
        "pattern": r"PostgreSQL\s+([\d.]+)",
        "version_group": 1,
        "vendor": "PostgreSQL Global Development Group",
    },
    "Redis": {
        "pattern": r"Redis server v=([\d.]+)",
        "version_group": 1,
        "vendor": "Redis Ltd",
    },
    "MongoDB": {
        "pattern": r"MongoDB\s+([\d.]+)",
        "version_group": 1,
        "vendor": "MongoDB Inc",
    },
    "Elasticsearch": {
        "pattern": r"\"name\":\s*\"([^\"]+)\",\s*\"cluster_name\":\s*\"([^\"]+)\"",
        "product_group": 1,
        "version_group": 2,
        "vendor": "Elastic",
    },
    "Memcached": {
        "pattern": r"STAT pid \d+",
        "product_group": 0,
        "vendor": "Memcached",
    },
}

CDN_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server": ["cloudflare"],
        "issuer": ["cloudflare"],
    },
    "AWS CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "via: cloudfront"],
        "server": ["cloudfront"],
        "issuer": ["amazon"],
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-restarts"],
        "server": ["fastly"],
        "issuer": ["fastly"],
    },
    "Akamai": {
        "headers": ["x-akamai-request-id", "akamai-origin-hop"],
        "server": ["akamai", "akamaighost"],
        "issuer": ["akamai"],
    },
    "Azure Front Door": {
        "headers": ["x-azure-ref", "x-fd-healthprobe"],
        "server": ["azurefd"],
        "issuer": ["microsoft"],
    },
    "Google Cloud CDN": {
        "headers": ["via: google", "x-goog-meta"],
        "server": ["gws", "gse"],
        "issuer": ["google"],
    },
    "Imperva / Incapsula CDN": {
        "headers": ["x-cdn: incapsula", "x-iinfo"],
        "server": ["incapsula"],
        "issuer": ["imperva", "incapsula"],
    },
}

WAF_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "AWS WAF": {
        "headers": ["x-amzn-errortype", "x-amz-apigw-id"],
        "cookies": ["aws-waf-token"],
        "vendor": "Amazon Web Services",
    },
    "Cloudflare WAF": {
        "headers": ["cf-ray"],
        "server": ["cloudflare"],
        "vendor": "Cloudflare",
    },
    "Google Cloud Armor": {
        "headers": ["via: google"],
        "body_patterns": ["google cloud armor"],
        "vendor": "Google",
    },
    "Imperva / Incapsula WAF": {
        "headers": ["x-iinfo", "x-cdn: incapsula"],
        "cookies": ["visid_incap"],
        "vendor": "Imperva",
    },
    "ModSecurity": {
        "headers": ["mod_security", "NOYB"],
        "server": ["mod_security", "modsecurity"],
        "vendor": "Trustwave / OWASP",
    },
    "Sucuri WAF": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri/cloudproxy"],
        "vendor": "Sucuri",
    },
    "Barracuda WAF": {
        "headers": ["barra_counter_session"],
        "cookies": ["barra_counter_session", "BNI__BIRT"],
        "vendor": "Barracuda Networks",
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-cnection: close"],
        "cookies": ["TS01", "BIGipServer"],
        "vendor": "F5 Networks",
    },
    "FortiWeb WAF": {
        "cookies": ["FORTIWAFSID"],
        "vendor": "Fortinet",
    },
}

PROXY_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "Nginx": {"server": ["nginx"], "headers": ["x-nginx"]},
    "HAProxy": {"headers": ["x-haproxy"], "server": ["haproxy"]},
    "Envoy": {"headers": ["x-envoy-upstream-service-time", "server: envoy"], "server": ["envoy"]},
    "Traefik": {"headers": ["x-traefik"], "server": ["traefik"]},
    "Apache": {"server": ["apache"], "headers": ["x-mod-pagespeed"]},
    "Caddy": {"server": ["caddy"]},
    "F5 BIG-IP": {"server": ["big-ip"], "headers": ["x-bigip"]},
    "IIS": {"server": ["microsoft-iis"]},
}

LOAD_BALANCER_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "AWS ALB/ELB": {"headers": ["awselb/2.0", "x-amz-cf-id"], "cookies": ["AWSALB", "AWSALBCORS"]},
    "Azure Load Balancer": {"headers": ["x-ms-request-id", "x-azure-ref"]},
    "GCP Load Balancer": {"headers": ["via: google"]},
    "HAProxy LB": {"headers": ["x-haproxy"], "server": ["haproxy"]},
    "F5 BIG-IP LTM": {"cookies": ["BIGipServer"]},
}

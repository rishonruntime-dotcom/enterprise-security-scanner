"""
Tests for network exposure scanner.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from scanner.network.exposure.scanner import NetworkExposureScanner, ScanTarget
from scanner.network.exposure.models import (
    PortInfo,
    PortState,
    TransportProtocol,
    NetworkExposureResult,
    ExposedServiceFinding,
    ServiceRisk,
    ServiceFingerprint,
    NetworkExposureSection,
)
from scanner.network.exposure.signatures import SERVICE_SIGNATURES, BANNER_SIGNATURES


class MockStreamReader:
    def __init__(self, data: bytes = b""):
        self._data = data
        self._pos = 0

    async def read(self, n: int) -> bytes:
        chunk = self._data[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk


class MockStreamWriter:
    def __init__(self, should_connect: bool = True, banner: bytes = b""):
        self.should_connect = should_connect
        self.banner = banner
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def write(self, data: bytes):
        pass

    async def drain(self):
        pass


class TestNetworkExposureScanner:
    """Test network exposure scanning."""

    @pytest.mark.asyncio
    async def test_scan_single_open_port(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (MockStreamReader(), MockStreamWriter())
            result = await scanner.scan("127.0.0.1", ports=[8080])
        
        assert len(result.open_ports) == 1
        assert result.open_ports[0].port == 8080
        assert result.open_ports[0].state == PortState.OPEN

    @pytest.mark.asyncio
    async def test_scan_single_closed_port(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError()):
            result = await scanner.scan("127.0.0.1", ports=[8080])
        
        assert len(result.open_ports) == 0
        assert 8080 in result.closed_ports

    @pytest.mark.asyncio
    async def test_banner_grabbing(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": True})
        
        banner_data = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (MockStreamReader(banner_data), MockStreamWriter())
            result = await scanner.scan("127.0.0.1", ports=[22])
        
        assert len(result.open_ports) == 1
        assert result.open_ports[0].banner is not None
        assert "OpenSSH" in result.open_ports[0].banner

    @pytest.mark.asyncio
    async def test_service_fingerprinting_from_banner(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": True})
        
        banner_data = b"220 (vsFTPd 3.0.5)\r\n"
        
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (MockStreamReader(banner_data), MockStreamWriter())
            result = await scanner.scan("127.0.0.1", ports=[21])
        
        assert len(result.open_ports) == 1
        assert result.open_ports[0].service_name == "FTP"
        assert result.open_ports[0].product == "vsFTPd"
        assert result.open_ports[0].version == "3.0.5"

    @pytest.mark.asyncio
    async def test_risk_assessment_ftp(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        port_info = PortInfo(port=21, state=PortState.OPEN, protocol=TransportProtocol.TCP, service_name="FTP", product="vsFTPd", version="3.0.5")
        finding = scanner._assess_risk(port_info, "127.0.0.1")
        
        assert finding is not None
        assert finding.severity == ServiceRisk.HIGH
        assert finding.port == 21
        assert "FTP" in finding.title

    @pytest.mark.asyncio
    async def test_risk_assessment_redis(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        port_info = PortInfo(port=6379, state=PortState.OPEN, protocol=TransportProtocol.TCP, service_name="Redis", product="Redis", version="7.0.0")
        finding = scanner._assess_risk(port_info, "127.0.0.1")
        
        assert finding is not None
        assert finding.severity == ServiceRisk.CRITICAL
        assert finding.port == 6379

    @pytest.mark.asyncio
    async def test_risk_assessment_https(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        port_info = PortInfo(port=443, state=PortState.OPEN, protocol=TransportProtocol.TCP, service_name="HTTPS", product="HTTPS")
        finding = scanner._assess_risk(port_info, "127.0.0.1")
        
        assert finding is None

    @pytest.mark.asyncio
    async def test_port_resolution(self):
        scanner = NetworkExposureScanner(config={"port_ranges": "1-10,20-30", "common_ports_only": False})
        ports = scanner._resolve_ports()
        assert len(ports) == 21
        assert 1 in ports
        assert 10 in ports
        assert 20 in ports
        assert 30 in ports

    @pytest.mark.asyncio
    async def test_common_ports_only(self):
        scanner = NetworkExposureScanner(config={"common_ports_only": True})
        ports = scanner._resolve_ports()
        assert len(ports) == 1023
        assert 1 in ports
        assert 1023 in ports

    @pytest.mark.asyncio
    async def test_service_fingerprint_creation(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        port_info = PortInfo(port=22, state=PortState.OPEN, protocol=TransportProtocol.TCP, service_name="SSH", product="OpenSSH", version="8.9")
        fingerprint = scanner._fingerprint_service(port_info)
        
        assert fingerprint.name == "SSH"
        assert fingerprint.product == "OpenSSH"
        assert fingerprint.version == "8.9"
        assert fingerprint.confidence >= 0.5

    @pytest.mark.asyncio
    async def test_tls_detection(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            
            with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
                mock_reader = MockStreamReader()
                mock_writer = MockStreamWriter()
                mock_writer.get_extra_info = MagicMock(return_value=MagicMock(
                    version=lambda: "TLSv1.3",
                    cipher=lambda: ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                    getpeercert=lambda: {
                        "subject": ((("organizationName", "Example Inc"),), (("commonName", "example.com"),)),
                        "issuer": ((("organizationName", "Example CA"),), (("commonName", "Example CA"),)),
                    }
                ))
                mock_conn.return_value = (mock_reader, mock_writer)
                
                tls_info = await scanner._check_tls("127.0.0.1", 443)
        
        assert tls_info is not None
        assert tls_info.get("version") == "TLSv1.3"

    @pytest.mark.asyncio
    async def test_full_scan_mode(self):
        scanner = NetworkExposureScanner(config={"full_scan": True})
        ports = scanner._resolve_ports()
        assert len(ports) == 65535
        assert 1 in ports
        assert 65535 in ports

    @pytest.mark.asyncio
    async def test_common_ports_mode(self):
        scanner = NetworkExposureScanner(config={"common_ports_only": True})
        ports = scanner._resolve_ports()
        assert len(ports) == 1023
        assert 1 in ports
        assert 1023 in ports

    @pytest.mark.asyncio
    async def test_configurable_port_ranges(self):
        scanner = NetworkExposureScanner(config={"port_ranges": "1-10,20-30", "common_ports_only": False})
        ports = scanner._resolve_ports()
        assert len(ports) == 21
        assert 1 in ports
        assert 10 in ports
        assert 20 in ports
        assert 30 in ports

    @pytest.mark.asyncio
    async def test_redis_anonymous_access_detection(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        redis_responses = [
            b"+PONG\r\n",
            b"# Server\r\nredis_version:7.0.0\r\nredis_git_sha1:00000000\r\n"
        ]
        response_iter = iter(redis_responses)
        
        async def mock_open_connection(*args, **kwargs):
            reader = MockStreamReader()
            writer = MockStreamWriter()
            original_read = reader.read
            async def patched_read(n):
                try:
                    return next(response_iter)
                except StopIteration:
                    return b""
            reader.read = patched_read
            return reader, writer
        
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            result = await scanner.scan("127.0.0.1", ports=[6379])
        
        assert len(result.open_ports) == 1
        assert result.open_ports[0].extra_info.get("anonymous_access") is True
        assert result.open_ports[0].version == "7.0.0"
        assert "redis_anonymous_access" in result.open_ports[0].checks

    @pytest.mark.asyncio
    async def test_redis_auth_required_detection(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        call_count = [0]
        async def mock_open_connection(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                reader = MockStreamReader(b"-NOAUTH Authentication required\r\n")
            else:
                reader = MockStreamReader(b"")
            writer = MockStreamWriter()
            return reader, writer
        
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            result = await scanner.scan("127.0.0.1", ports=[6379])
        
        assert len(result.open_ports) == 1
        assert result.open_ports[0].extra_info.get("auth_required") is True
        assert "redis_auth_required" in result.open_ports[0].checks

    @pytest.mark.asyncio
    async def test_severity_boosted_by_anonymous_access(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        port_info = PortInfo(
            port=6379,
            state=PortState.OPEN,
            protocol=TransportProtocol.TCP,
            service_name="Redis",
            product="Redis",
            version="7.0.0",
            checks=["redis_anonymous_access"],
            extra_info={"anonymous_access": True}
        )
        finding = scanner._assess_risk(port_info, "127.0.0.1")
        
        assert finding is not None
        assert finding.severity == ServiceRisk.CRITICAL
        assert finding.anonymous_access is True
        assert finding.misconfiguration_detected is True
        assert finding.risk_score > 8.0

    @pytest.mark.asyncio
    async def test_severity_dampened_by_authentication(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        port_info = PortInfo(
            port=6379,
            state=PortState.OPEN,
            protocol=TransportProtocol.TCP,
            service_name="Redis",
            product="Redis",
            version="7.0.0",
            checks=["redis_auth_required"],
            extra_info={"auth_required": True}
        )
        finding = scanner._assess_risk(port_info, "127.0.0.1")
        
        assert finding is not None
        assert finding.severity == ServiceRisk.HIGH
        assert finding.is_authenticated is True
        assert finding.anonymous_access is False

    @pytest.mark.asyncio
    async def test_report_section_generation(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": False})
        
        result = NetworkExposureResult(
            target_host="example.com",
            ports_scanned=100,
            open_ports=[
                PortInfo(port=80, state=PortState.OPEN, protocol=TransportProtocol.TCP, service_name="HTTP", product="nginx", version="1.25", tls_version=None, http_version="HTTP/1.1", server_software="nginx", checks=["http_header_probe"]),
                PortInfo(port=443, state=PortState.OPEN, protocol=TransportProtocol.TCP, service_name="HTTPS", product="nginx", version="1.25", tls_version="TLSv1.3", http_version="HTTP/2", server_software="nginx", reverse_proxy="Cloudflare", checks=["http_header_probe", "tls_detected"]),
                PortInfo(port=6379, state=PortState.OPEN, protocol=TransportProtocol.TCP, service_name="Redis", product="Redis", version="7.0.0", checks=["redis_anonymous_access"], extra_info={"anonymous_access": True}),
            ],
            filtered_ports=[1, 2, 3],
            closed_ports=[4, 5, 6],
            services=[
                ServiceFingerprint(name="HTTP", product="nginx", version="1.25", protocol="tcp", confidence=0.9),
                ServiceFingerprint(name="HTTPS", product="nginx", version="1.25", protocol="tcp", confidence=0.9),
                ServiceFingerprint(name="Redis", product="Redis", version="7.0.0", protocol="tcp", confidence=0.8),
            ],
            scan_duration_seconds=1.5,
        )
        
        section = scanner.build_report_section(result)
        
        assert section.target_host == "example.com"
        assert section.open_ports_count == 3
        assert section.filtered_ports_count == 3
        assert section.closed_ports_count == 3
        assert section.risky_services_count == 1
        assert len(section.open_ports) == 3
        assert len(section.services_summary) == 3
        
        port_443 = next(p for p in section.open_ports if p["port"] == 443)
        assert port_443["tls_version"] == "TLSv1.3"
        assert port_443["http_version"] == "HTTP/2"
        assert port_443["reverse_proxy"] == "Cloudflare"
        
        port_6379 = next(p for p in section.open_ports if p["port"] == 6379)
        assert port_6379["service"] == "Redis"
        assert "redis_anonymous_access" in port_6379["checks"]

    @pytest.mark.asyncio
    async def test_no_duplicate_technology_entries(self):
        from scanner.repositories.technology_repo import SQLAlchemyTechnologyRepository
        from scanner.database.models.technology import TechnologyORM
        from unittest.mock import AsyncMock
        
        mock_session = AsyncMock()
        repo = SQLAlchemyTechnologyRepository(session=mock_session)
        
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        
        tech1 = TechnologyORM(
            id="1",
            scan_id="scan1",
            name="Redis",
            category="Network Service",
            version="7.0.0",
            vendor="Redis",
            confidence=0.9,
            target_url="http://example.com",
        )
        
        result1 = await repo.upsert(tech1)
        result2 = await repo.upsert(tech1)
        
        assert result1.id == result2.id
        assert mock_session.execute.call_count == 2

    @pytest.mark.asyncio
    async def test_service_probe_improves_fingerprinting(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": True})
        
        banner_data = b"Server: nginx/1.25.3\r\n"
        
        async def mock_open_connection(*args, **kwargs):
            reader = MockStreamReader(b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: text/html\r\n\r\n")
            writer = MockStreamWriter()
            return reader, writer
        
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            result = await scanner.scan("127.0.0.1", ports=[80])
        
        assert len(result.open_ports) == 1
        assert result.open_ports[0].product == "nginx/1.25.3"
        assert result.open_ports[0].version == "1.25"
        assert result.open_ports[0].server_software == "nginx/1.25.3"
        assert result.open_ports[0].http_version == "HTTP/1.1"

    @pytest.mark.asyncio
    async def test_edge_infrastructure_detection(self):
        scanner = NetworkExposureScanner(config={"timeout": 0.1, "concurrency": 10, "banner_grab": True})

        banner_text = b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3 cloudflare\r\ncf-ray: 7f123456789\r\nx-amzn-errortype: AccessDeniedException\r\n\r\n"

        async def mock_open_connection(*args, **kwargs):
            return MockStreamReader(banner_text), MockStreamWriter()

        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            result = await scanner.scan("127.0.0.1", ports=[443])

        assert len(result.open_ports) == 1
        svc = result.open_ports[0].detected_service
        assert svc is not None
        assert svc.cdn_info is not None and svc.cdn_info.detected is True
        assert svc.cdn_info.provider_name == "Cloudflare"
        assert svc.waf_info is not None and svc.waf_info.detected is True
        assert svc.waf_info.waf_name == "AWS WAF"
        assert svc.proxy_info is not None and svc.proxy_info.detected is True

"""
Database schema upgrade utilities.
Adds missing columns to existing SQLite tables during development.
"""
import sqlalchemy as sa
from sqlalchemy import text


async def upgrade_schema(engine) -> None:
    """Upgrade database schema by adding missing columns."""
    async with engine.begin() as conn:
        # Add missing columns to findings table
        findings_columns = await conn.run_sync(
            lambda sync_conn: [row[1] for row in sync_conn.execute(text("PRAGMA table_info(findings)"))]
        )
        
        if "endpoint_class" not in findings_columns:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN endpoint_class VARCHAR"))
        if "asset_category" not in findings_columns:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN asset_category VARCHAR"))
        if "why_detected" not in findings_columns:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN why_detected TEXT"))
        if "how_verified" not in findings_columns:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN how_verified VARCHAR"))
        if "severity_reason" not in findings_columns:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN severity_reason TEXT"))
        if "false_positive_reasons" not in findings_columns:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN false_positive_reasons TEXT"))
        if "raw_risk" not in findings_columns:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN raw_risk TEXT"))
        if "false_positive_probability" not in findings_columns:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN false_positive_probability FLOAT DEFAULT 0.0"))
        if "original_severity" not in findings_columns:
            await conn.execute(text("ALTER TABLE findings ADD COLUMN original_severity VARCHAR"))

        # Add missing columns to scans table
        scans_columns = await conn.run_sync(
            lambda sync_conn: [row[1] for row in sync_conn.execute(text("PRAGMA table_info(scans)"))]
        )
        
        if "javascript_files_analyzed" not in scans_columns:
            await conn.execute(text("ALTER TABLE scans ADD COLUMN javascript_files_analyzed INTEGER DEFAULT 0"))
        if "assets_skipped" not in scans_columns:
            await conn.execute(text("ALTER TABLE scans ADD COLUMN assets_skipped INTEGER DEFAULT 0"))
        if "third_party_assets" not in scans_columns:
            await conn.execute(text("ALTER TABLE scans ADD COLUMN third_party_assets INTEGER DEFAULT 0"))
        if "network_open_ports" not in scans_columns:
            await conn.execute(text("ALTER TABLE scans ADD COLUMN network_open_ports INTEGER DEFAULT 0"))
        if "network_services_detected" not in scans_columns:
            await conn.execute(text("ALTER TABLE scans ADD COLUMN network_services_detected INTEGER DEFAULT 0"))
        if "network_risky_services" not in scans_columns:
            await conn.execute(text("ALTER TABLE scans ADD COLUMN network_risky_services INTEGER DEFAULT 0"))
        if "network_exposure_result" not in scans_columns:
            await conn.execute(text("ALTER TABLE scans ADD COLUMN network_exposure_result TEXT"))

        # Add missing columns to technologies table
        tech_columns = await conn.run_sync(
            lambda sync_conn: [row[1] for row in sync_conn.execute(text("PRAGMA table_info(technologies)"))]
        )

        if "detection_method" not in tech_columns:
            await conn.execute(text("ALTER TABLE technologies ADD COLUMN detection_method VARCHAR DEFAULT 'fingerprinting'"))
        if "detection_methods" not in tech_columns:
            await conn.execute(text("ALTER TABLE technologies ADD COLUMN detection_methods TEXT"))
        if "detection_source" not in tech_columns:
            await conn.execute(text("ALTER TABLE technologies ADD COLUMN detection_source VARCHAR DEFAULT 'Passive'"))
        if "confidence_reason" not in tech_columns:
            await conn.execute(text("ALTER TABLE technologies ADD COLUMN confidence_reason TEXT"))
        if "evidence_count" not in tech_columns:
            await conn.execute(text("ALTER TABLE technologies ADD COLUMN evidence_count INTEGER DEFAULT 1"))
        if "observed_on" not in tech_columns:
            await conn.execute(text("ALTER TABLE technologies ADD COLUMN observed_on VARCHAR"))

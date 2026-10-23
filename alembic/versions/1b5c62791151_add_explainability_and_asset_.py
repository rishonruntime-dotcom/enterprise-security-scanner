"""add_explainability_and_asset_classification_to_findings

Revision ID: 1b5c62791151
Revises: 110b2877c4f4
Create Date: 2026-08-04 16:57:00.083170

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1b5c62791151'
down_revision: Union[str, Sequence[str], None] = '110b2877c4f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('findings', sa.Column('endpoint_class', sa.String(), nullable=True))
    op.add_column('findings', sa.Column('asset_category', sa.String(), nullable=True))
    op.add_column('findings', sa.Column('why_detected', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('how_verified', sa.String(), nullable=True))
    op.add_column('findings', sa.Column('severity_reason', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('false_positive_reasons', sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('findings', 'false_positive_reasons')
    op.drop_column('findings', 'severity_reason')
    op.drop_column('findings', 'how_verified')
    op.drop_column('findings', 'why_detected')
    op.drop_column('findings', 'asset_category')
    op.drop_column('findings', 'endpoint_class')

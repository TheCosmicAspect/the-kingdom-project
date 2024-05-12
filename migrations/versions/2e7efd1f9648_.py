"""empty message

Revision ID: 2e7efd1f9648
Revises: 
Create Date: 2024-04-17 16:43:25.603535

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2e7efd1f9648'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('rank',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=50), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('user_rank',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('rank_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['rank_id'], ['rank.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('user_id', 'rank_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user_rank')
    op.drop_table('rank')
    # ### end Alembic commands ###
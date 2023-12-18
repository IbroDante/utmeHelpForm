"""updates

Revision ID: 9b12ec2a0069
Revises: 2cbc1eefd39b
Create Date: 2023-12-12 11:56:15.855719

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '9b12ec2a0069'
down_revision = '2cbc1eefd39b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('form', schema=None) as batch_op:
        batch_op.alter_column('sender_id',
               existing_type=mysql.INTEGER(),
               nullable=True)
        batch_op.alter_column('user_id',
               existing_type=mysql.INTEGER(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('form', schema=None) as batch_op:
        batch_op.alter_column('user_id',
               existing_type=mysql.INTEGER(),
               nullable=False)
        batch_op.alter_column('sender_id',
               existing_type=mysql.INTEGER(),
               nullable=False)

    # ### end Alembic commands ###
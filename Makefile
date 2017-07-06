MODULE_big = pguecc
EXTENSION = pguecc
DATA = pguecc--1.0.sql
DOCS = README.rst
SRCS = pguecc.c micro-ecc-601bd1/uECC.c
OBJS = $(SRCS:.c=.o)
REGRESS = pguecc_test_raw pguecc_test_public

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

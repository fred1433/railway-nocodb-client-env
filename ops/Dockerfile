# One image for bootstrap, backup, checks and restore. Same client tools as the server.
FROM postgres:18.6@sha256:3a4264520e121176619f54ff867d12774bc81e95e7b84db58d63bccdb6144b81
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-psycopg curl age ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY ops /app/ops
COPY checks /app/checks
COPY reference/seed.sql /app/reference/seed.sql
WORKDIR /app
ENTRYPOINT ["python3", "-u", "/app/ops/main.py"]

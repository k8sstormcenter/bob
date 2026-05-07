FROM postgres:16

# Install PL extensions needed for CVE attack suite:
#   plpython3u — T1059 PL/Python RCE
#   plperlu    — T1059 PL/Perl RCE
#   dblink     — T1190 SSRF (already in contrib, just ensure available)
# The base postgres:16 (Debian) image includes contrib extensions.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       postgresql-plpython3-16 \
       postgresql-plperl-16 \
    && rm -rf /var/lib/apt/lists/*

# PARALLAX / STRATA live-execution AD range - a REAL Active Directory Domain Controller.
#
# This is the Railway-native equivalent of a GOAD/Ludus Windows range. Railway cannot run Windows
# VMs or nested virtualization, so the live range is a genuine Samba Active Directory Domain
# Controller (AD DS): real LDAP/Kerberos/SMB/DNS, real users, SPNs, group memberships and ACLs,
# and real attack primitives. Candidates attack it with the same offensive tooling they would use
# against a Windows DC:
#   - bloodhound-python / RustHound  -> collect the graph over LDAP
#   - impacket GetUserSPNs           -> Kerberoasting (TGS-REP, port 88)
#   - impacket GetNPUsers            -> AS-REP roasting (port 88)
#   - bloodyAD / dacledit            -> ACL abuse (ForceChangePassword, GenericAll)
#   - impacket secretsdump -just-dc  -> DCSync over the SMB named pipe (\drsuapi on 445)
#
# The planted attack path mirrors ad_range.generate_domain():
#   foothold (ForceChangePassword) -> Kerberoastable service account -> group with DCSync rights
#   -> DCSync of the domain (Administrator / krbtgt).
#
# Proof of compromise is the Administrator NT hash, obtainable ONLY by DCSync (the candidate never
# learns the password). The portal verifies the submitted hash against MD4(UTF-16LE(adminpass))
# derived from the shared ADRANGE_ADMIN_PASSWORD secret, so a pass is cryptographic proof of a real
# domain compromise and cannot be faked.
#
# Build/deploy is manual (deploy/ is outside the portal autodeploy hold). Deploy ONLY to a
# NONPRODUCTION environment; this service deliberately exposes an attackable DC on the internet.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
# Samba AD DC + tooling. krb5-config/winbind pulled for completeness; python3-samba for the seed.
RUN apt-get update && apt-get install -y --no-install-recommends \
        samba samba-ad-provision samba-dsdb-modules samba-vfs-modules \
        smbclient winbind libnss-winbind libpam-winbind \
        krb5-user krb5-config \
        python3 python3-samba ldb-tools \
        ca-certificates procps iproute2 dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    # Remove the default smb.conf so `samba-tool domain provision` writes a clean AD DC config.
    && rm -f /etc/samba/smb.conf

# DEBUG ONLY (nonprod): several DCSync clients so the ADRANGE_DIAG loopback self-test can find one
# that parses Samba 4.17's DRSGetNCChanges reply (stock impacket 0.11.x-0.13.x cannot: "code 0x0
# ERROR_SUCCESS"). Each install is best-effort (|| true) so one flaky dep cannot fail the DC build;
# the self-test guards on what is actually present. Revert once the proof client is chosen; the DC
# should not ship with attack tooling on it.
RUN apt-get update && apt-get install -y --no-install-recommends python3-pip python3-venv git pipx \
    && rm -rf /var/lib/apt/lists/*
# 1) stock impacket 0.13.1 (baseline)
RUN pip3 install --break-system-packages --no-cache-dir 'impacket==0.13.1' || true
# 2) impacket git master in its own venv (may carry a Samba DRS fix not yet released)
RUN python3 -m venv /opt/impkt-master \
    && /opt/impkt-master/bin/pip install --no-cache-dir 'impacket @ git+https://github.com/fortra/impacket.git' || true
# 3) netexec (ships its own impacket pin; known to handle Samba AD --ntds)
RUN PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install netexec || true

COPY seed.py /opt/adrange/seed.py
COPY proof_server.py /opt/adrange/proof_server.py
COPY socks_scoped.py /opt/adrange/socks_scoped.py
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# The AD DC's own ports (53/88/389/445/636/3268 ...) stay on the container; candidates reach them by
# pivoting through the SOCKS proxy on 1080, which is the ONE port the Railway TCP proxy exposes
# publicly (Railway allows a single TCP proxy per service, so a SOCKS pivot gives access to every AD
# port at its standard number via proxychains). 9443 is the PRIVATE-only proof server (never proxied).
EXPOSE 1080 53 88 135 389 445 464 636 3268 3269 9443

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

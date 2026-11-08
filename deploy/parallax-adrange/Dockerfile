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
        samba samba-ad-provision smbclient winbind libnss-winbind libpam-winbind \
        krb5-user krb5-config \
        python3 python3-samba ldb-tools \
        ca-certificates procps iproute2 dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    # Remove the default smb.conf so `samba-tool domain provision` writes a clean AD DC config.
    && rm -f /etc/samba/smb.conf

COPY seed.py /opt/adrange/seed.py
COPY proof_server.py /opt/adrange/proof_server.py
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# AD DC service ports. The Railway TCP proxy maps a public port to each of the candidate-facing
# ports; 53/88/389/445/636/3268 are the set the attack chain needs. 9443 is the PRIVATE-only proof
# server (never proxied publicly) the portal reads expected proof material from.
EXPOSE 53 88 135 389 445 464 636 3268 3269 9443

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

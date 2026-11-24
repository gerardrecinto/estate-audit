import base64
from datetime import date
from pathlib import Path

from estate_audit import ldapaudit

SAMPLE = Path(__file__).parent.parent / "data" / "sample.ldif"
AS_OF = date(2026, 11, 24)


def checks_of(findings):
    return {(f.check, f.message) for f in findings}


def test_sample_dump_has_exactly_the_seeded_problems():
    f = ldapaudit.audit(ldapaudit.parse_ldif(SAMPLE.read_text()), AS_OF)
    assert checks_of(f) == {
        ("duplicate-uidnumber", "uidNumber 10002 shared by bob, carol"),
        ("expired-with-shell", "bob expired but still has /bin/bash"),
        ("missing-attribute", "dave has no loginShell"),
        ("orphan-gid", "dave primary gid 2000 has no group"),
        ("stale-member", "group staff lists ghost, who has no account"),
    }


def test_folded_and_base64_values():
    cn = base64.b64encode("Zoë".encode()).decode()
    text = f"dn: uid=z,dc=x\nobjectClass: posixAccount\nuid: z\ncn:: {cn}\nhomeDirectory: /home/\n z\n"
    e = ldapaudit.parse_ldif(text)[0]
    assert e["cn"] == ["Zoë"] and e["homeDirectory"] == ["/home/z"]


def test_ldapsearch_noise_is_ignored():
    text = "# extended LDIF\n# search result\nsearch: 2\nresult: 0 Success\n\ndn: uid=a,dc=x\nuid: a\n\n# numResponses: 2\n"
    assert len(ldapaudit.parse_ldif(text)) == 1


def test_expired_account_with_nologin_is_fine():
    text = ("dn: cn=g,dc=x\nobjectClass: posixGroup\ncn: g\ngidNumber: 1\n\n"
            "dn: uid=a,dc=x\nobjectClass: posixAccount\nuid: a\nuidNumber: 5\ngidNumber: 1\n"
            "homeDirectory: /h\nloginShell: /sbin/nologin\nshadowExpire: 100\n")
    assert ldapaudit.audit(ldapaudit.parse_ldif(text), AS_OF) == []


def test_not_yet_expired_is_fine():
    days = (date(2027, 1, 1) - date(1970, 1, 1)).days
    text = (f"dn: cn=g,dc=x\nobjectClass: posixGroup\ncn: g\ngidNumber: 1\n\n"
            f"dn: uid=a,dc=x\nobjectClass: posixAccount\nuid: a\nuidNumber: 5\ngidNumber: 1\n"
            f"homeDirectory: /h\nloginShell: /bin/bash\nshadowExpire: {days}\n")
    assert ldapaudit.audit(ldapaudit.parse_ldif(text), AS_OF) == []

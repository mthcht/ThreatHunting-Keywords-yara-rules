rule DavRelayUp
{
    meta:
        description = "Detection patterns for the tool 'DavRelayUp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DavRelayUp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string1 = /.{0,1000}\/DavRelayUp\.git.{0,1000}/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string2 = /.{0,1000}\/DavRelayUp\/.{0,1000}/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string3 = /.{0,1000}DavRelayUp\.csproj.{0,1000}/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string4 = /.{0,1000}DavRelayUp\.exe.{0,1000}/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string5 = /.{0,1000}DavRelayUp\.sln.{0,1000}/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string6 = /.{0,1000}DavRelayUp\-master.{0,1000}/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string7 = /.{0,1000}GoRelayServer\.dll.{0,1000}/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string8 = /.{0,1000}ShorSec\/DavRelayUp.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

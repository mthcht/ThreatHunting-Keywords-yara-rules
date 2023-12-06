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
        $string1 = /\/DavRelayUp\.git/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string2 = /\/DavRelayUp\// nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string3 = /DavRelayUp\.csproj/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string4 = /DavRelayUp\.exe/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string5 = /DavRelayUp\.sln/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string6 = /DavRelayUp\-master/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string7 = /GoRelayServer\.dll/ nocase ascii wide
        // Description: DavRelayUp - a universal no-fix local privilege escalation in domain-joined windows workstations where LDAP signing is not enforced
        // Reference: https://github.com/ShorSec/DavRelayUp
        $string8 = /ShorSec\/DavRelayUp/ nocase ascii wide

    condition:
        any of them
}

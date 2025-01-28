rule antSword
{
    meta:
        description = "Detection patterns for the tool 'antSword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "antSword"
        rule_category = "signature_keyword"

    strings:
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string1 = /Backdoor\.ASP\.WebShell\.ez/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string2 = /Backdoor\.ASP\.WEBSHELL\.THFBIBC/ nocase ascii wide
        // Description: cross-platform website management toolkit - abused by attackers - supports the use of web shells
        // Reference: https://github.com/AntSwordProject/antSword
        $string3 = /Backdoor\:ASP\/Dirtelti\.HA/ nocase ascii wide

    condition:
        any of them
}

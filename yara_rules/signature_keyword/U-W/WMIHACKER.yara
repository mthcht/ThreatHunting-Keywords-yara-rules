rule WMIHACKER
{
    meta:
        description = "Detection patterns for the tool 'WMIHACKER' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMIHACKER"
        rule_category = "signature_keyword"

    strings:
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string1 = /HackTool\.VBS\.WMIHACKER/ nocase ascii wide

    condition:
        any of them
}

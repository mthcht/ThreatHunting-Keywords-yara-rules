rule Invoke_ZeroLogon
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ZeroLogon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ZeroLogon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Zerologon CVE exploitation
        // Reference: https://github.com/BC-SECURITY/Invoke-ZeroLogon
        $string1 = /Invoke\-ZeroLogon/ nocase ascii wide

    condition:
        any of them
}

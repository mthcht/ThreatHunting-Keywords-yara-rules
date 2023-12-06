rule kekeo
{
    meta:
        description = "Detection patterns for the tool 'kekeo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kekeo"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: access the LSA (Local Security Authority) and manipulate Kerberos tickets. potentially allowing adversaries to gain unauthorized access to Active Directory resources and CIFS file shares
        // Reference: https://github.com/gentilkiwi/kekeo
        $string1 = /kirbikator\.exe/ nocase ascii wide

    condition:
        any of them
}

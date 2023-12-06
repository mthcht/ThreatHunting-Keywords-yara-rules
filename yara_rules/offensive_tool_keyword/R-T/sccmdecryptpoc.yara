rule sccmdecryptpoc
{
    meta:
        description = "Detection patterns for the tool 'sccmdecryptpoc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sccmdecryptpoc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SCCM Account Password Decryption POC
        // Reference: https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1
        $string1 = /sccmdecryptpoc\./ nocase ascii wide

    condition:
        any of them
}

rule SMBGhost_RCE_PoC
{
    meta:
        description = "Detection patterns for the tool 'SMBGhost_RCE_PoC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBGhost_RCE_PoC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RCE PoC for CVE-2020-0796 SMBGhost
        // Reference: https://github.com/chompie1337/SMBGhost_RCE_PoC
        $string1 = /\/SMBGhost_RCE/ nocase ascii wide
        // Description: RCE PoC for CVE-2020-0796 SMBGhost
        // Reference: https://github.com/chompie1337/SMBGhost_RCE_PoC
        $string2 = /smb_win\.py/ nocase ascii wide

    condition:
        any of them
}

rule smb_scanner
{
    meta:
        description = "Detection patterns for the tool 'smb-scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smb-scanner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SMB Scanner tool
        // Reference: https://github.com/TechnicalMujeeb/smb-scanner
        $string1 = /smbscan/ nocase ascii wide
        // Description: SMB Scanner tool
        // Reference: https://github.com/TechnicalMujeeb/smb-scanner
        $string2 = /smb\-scanner/ nocase ascii wide

    condition:
        any of them
}

rule PstPassword
{
    meta:
        description = "Detection patterns for the tool 'PstPassword' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PstPassword"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: recover the PST passwords of Outlook
        // Reference: https://www.nirsoft.net/utils/pst_password.html
        $string1 = /PstPassword\.exe/ nocase ascii wide
        // Description: recover the PST passwords of Outlook
        // Reference: https://www.nirsoft.net/utils/pst_password.html
        $string2 = /pstpassword\.zip/ nocase ascii wide
        // Description: recover the PST passwords of Outlook
        // Reference: https://www.nirsoft.net/utils/pst_password.html
        $string3 = /pstpassword_setup\.exe/ nocase ascii wide

    condition:
        any of them
}

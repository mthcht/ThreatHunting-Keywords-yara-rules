rule certutil
{
    meta:
        description = "Detection patterns for the tool 'certutil' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "certutil"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: LOLBAS execution - downloading payload from discord with certutil
        // Reference: N/A
        $string1 = /certutil\.exe\s\-urlcache\s\-split\s\-f\s.{0,1000}https\:\/\/cdn\.discordapp\.com\/attachments\// nocase ascii wide
        // Description: Certutil download behavior observed by the Dispossessor ransomware group
        // Reference: N/A
        $string2 = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttp.{0,1000}\.bat\sC\:\\ProgramData\\/ nocase ascii wide
        // Description: Certutil download behavior observed by the Dispossessor ransomware group
        // Reference: N/A
        $string3 = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttp.{0,1000}\.ps1\sC\:\\ProgramData\\/ nocase ascii wide
        // Description: Certutil download behavior observed by the Dispossessor ransomware group
        // Reference: N/A
        $string4 = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttp.{0,1000}\.vbs\sC\:\\ProgramData\\/ nocase ascii wide
        // Description: Certutil Download from github
        // Reference: N/A
        $string5 = /certutil\.exe\s\-urlcache\s\-split\s\-f\shttps\:\/\/raw\.githubusercontent\.com\// nocase ascii wide

    condition:
        any of them
}

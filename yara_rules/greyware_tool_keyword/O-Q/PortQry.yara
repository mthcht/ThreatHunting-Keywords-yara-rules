rule PortQry
{
    meta:
        description = "Detection patterns for the tool 'PortQry' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PortQry"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string1 = /\/PortQry\.exe/ nocase ascii wide
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string2 = /\/PortQryV2\.exe/ nocase ascii wide
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string3 = /\\PortQry\.exe/ nocase ascii wide
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string4 = /\\PortQryV2\.exe/ nocase ascii wide
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string5 = /\\PortQryV2\\/ nocase ascii wide
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string6 = /\\RunOnce\\wextract_cleanup0/ nocase ascii wide
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string7 = /6471c5190a99e3d1f337fcfef1fc410e8d487b66e093f924700e186cbd398dc0/ nocase ascii wide
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string8 = /PortQry\sCommand\sLine\sPort\sScanner/ nocase ascii wide
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string9 = /portqry\s\-local/ nocase ascii wide
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string10 = /portqry\s\-n\s/ nocase ascii wide
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string11 = /portqry\s\-wpid/ nocase ascii wide
        // Description: Microsoft port scanning tool abused by threat actors
        // Reference: https://www.microsoft.com/en-us/download/details.aspx?id=17148
        $string12 = /portqry\s\-wport/ nocase ascii wide

    condition:
        any of them
}

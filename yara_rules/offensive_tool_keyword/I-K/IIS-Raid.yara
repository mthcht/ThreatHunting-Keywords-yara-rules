rule IIS_Raid
{
    meta:
        description = "Detection patterns for the tool 'IIS-Raid' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IIS-Raid"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string1 = /\siis_controller\.py/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string2 = /\s\-\-url\s\-\-password\sSIMPLEPASS/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string3 = /\/iis_controller\.py/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string4 = /\/IIS\-Raid\.git/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string5 = /\\iis_controller\.py/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string6 = /\\Windows\\Temp\\creds\.db/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string7 = /0x09AL\/IIS\-Raid/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string8 = /IIS\-Backdoor\./ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string9 = /IIS\-Raid\-master/ nocase ascii wide

    condition:
        any of them
}

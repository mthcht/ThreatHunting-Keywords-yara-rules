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
        $string1 = /.{0,1000}\siis_controller\.py.{0,1000}/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string2 = /.{0,1000}\s\-\-url\s\-\-password\sSIMPLEPASS.{0,1000}/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string3 = /.{0,1000}\/iis_controller\.py.{0,1000}/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string4 = /.{0,1000}\/IIS\-Raid\.git.{0,1000}/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string5 = /.{0,1000}\\iis_controller\.py.{0,1000}/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string6 = /.{0,1000}\\Windows\\Temp\\creds\.db.{0,1000}/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string7 = /.{0,1000}0x09AL\/IIS\-Raid.{0,1000}/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string8 = /.{0,1000}IIS\-Backdoor\..{0,1000}/ nocase ascii wide
        // Description: A native backdoor module for Microsoft IIS
        // Reference: https://github.com/0x09AL/IIS-Raid
        $string9 = /.{0,1000}IIS\-Raid\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

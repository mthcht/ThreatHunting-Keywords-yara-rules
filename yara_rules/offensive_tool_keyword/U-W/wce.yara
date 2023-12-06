rule wce
{
    meta:
        description = "Detection patterns for the tool 'wce' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wce"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string1 = /\/returnvar\/wce\// nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string2 = /\/share\/windows\-resources\/wce/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string3 = /\/wce32\.exe/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string4 = /\/wce64\.exe/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string5 = /\/wce\-beta\.zip/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string6 = /\\wce32\.exe/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string7 = /\\wce64\.exe/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string8 = /\\wce\-beta\.zip/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string9 = /apt\sinstall\swce/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string10 = /wce\s\-i\s3e5\s\-s\s/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string11 = /wce.{0,1000}getlsasrvaddr\.exe/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string12 = /wce\-master\.zip/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string13 = /wce\-universal\.exe/ nocase ascii wide

    condition:
        any of them
}

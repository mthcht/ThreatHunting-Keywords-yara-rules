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
        $string1 = /.{0,1000}\/returnvar\/wce\/.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string2 = /.{0,1000}\/share\/windows\-resources\/wce.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string3 = /.{0,1000}\/wce32\.exe.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string4 = /.{0,1000}\/wce64\.exe.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string5 = /.{0,1000}\/wce\-beta\.zip.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string6 = /.{0,1000}\\wce32\.exe.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string7 = /.{0,1000}\\wce64\.exe.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string8 = /.{0,1000}\\wce\-beta\.zip.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string9 = /.{0,1000}apt\sinstall\swce.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string10 = /.{0,1000}wce\s\-i\s3e5\s\-s\s.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string11 = /.{0,1000}wce.{0,1000}getlsasrvaddr\.exe.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string12 = /.{0,1000}wce\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string13 = /.{0,1000}wce\-universal\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

rule RaRCE
{
    meta:
        description = "Detection patterns for the tool 'RaRCE' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RaRCE"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string1 = /.{0,1000}\sCVE\-2023\-38831\-RaRCE.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string2 = /.{0,1000}\srarce\.py.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string3 = /.{0,1000}\/CVE\-2023\-38831\-RaRCE.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string4 = /.{0,1000}\/rarce\.py.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string5 = /.{0,1000}\\rarce\.py.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string6 = /.{0,1000}from\srarce\simport\sexploit.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string7 = /.{0,1000}pip\sinstall\srarce.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string8 = /.{0,1000}python\s\-m\srarce\s.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string9 = /.{0,1000}rarce\s.{0,1000}\.pdf\s.{0,1000}\.rar.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string10 = /.{0,1000}rarce\s.{0,1000}\.rar.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string11 = /.{0,1000}rarce\-1\.0\.0\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string12 = /.{0,1000}rarce\-1\.0\.0\-py3\-none\-any\.whl.{0,1000}/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string13 = /.{0,1000}totally\slegit\spdf\.pdf.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

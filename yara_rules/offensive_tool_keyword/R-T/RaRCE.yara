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
        $string1 = /\sCVE\-2023\-38831\-RaRCE/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string2 = /\srarce\.py/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string3 = /\/CVE\-2023\-38831\-RaRCE/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string4 = /\/rarce\.py/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string5 = /\\rarce\.py/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string6 = /from\srarce\simport\sexploit/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string7 = /pip\sinstall\srarce/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string8 = /python\s\-m\srarce\s/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string9 = /rarce\s.{0,1000}\.pdf\s.{0,1000}\.rar/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string10 = /rarce\s.{0,1000}\.rar/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string11 = /rarce\-1\.0\.0\.tar\.gz/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string12 = /rarce\-1\.0\.0\-py3\-none\-any\.whl/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string13 = /totally\slegit\spdf\.pdf/ nocase ascii wide

    condition:
        any of them
}

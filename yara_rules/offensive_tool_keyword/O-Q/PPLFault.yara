rule PPLFault
{
    meta:
        description = "Detection patterns for the tool 'PPLFault' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLFault"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string1 = /.{0,1000}\/DumpShellcode\/.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string2 = /.{0,1000}\/Nofault\.exe.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string3 = /.{0,1000}\/PPLFault\/.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string4 = /.{0,1000}\\GodFault\..{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string5 = /.{0,1000}\\Nofault\.exe.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string6 = /.{0,1000}\\PPLFault.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string7 = /.{0,1000}DumpShellcode\..{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string8 = /.{0,1000}DumpShellcode\\.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string9 = /.{0,1000}EventAggregation\.dll\.bak.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string10 = /.{0,1000}EventAggregation\.dll\.patched.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string11 = /.{0,1000}EventAggregationPH\.dll.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string12 = /.{0,1000}gabriellandau\/PPLFault.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string13 = /.{0,1000}GMShellcode.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string14 = /.{0,1000}GMShellcode\..{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string15 = /.{0,1000}GMShellcode\\.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string16 = /.{0,1000}GodFault\.exe.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string17 = /.{0,1000}GodFault\\GodFault.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string18 = /.{0,1000}HIJACK_DLL_PATH.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string19 = /.{0,1000}lsass\.dmp.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string20 = /.{0,1000}NoFault\\NoFault\..{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string21 = /.{0,1000}PPLFault\..{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string22 = /.{0,1000}PPLFault\.exe.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string23 = /.{0,1000}PPLFault\-Localhost\-SMB\.ps1.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string24 = /.{0,1000}PPLFaultPayload\.dll.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string25 = /.{0,1000}PPLFaultTemp.{0,1000}/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string26 = /.{0,1000}smbserver\.py\s\-payload.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

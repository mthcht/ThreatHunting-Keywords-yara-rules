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
        $string1 = /\/DumpShellcode\// nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string2 = /\/Nofault\.exe/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string3 = /\/PPLFault\// nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string4 = /\\GodFault\./ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string5 = /\\Nofault\.exe/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string6 = /\\PPLFault/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string7 = /DumpShellcode\./ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string8 = /DumpShellcode\\/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string9 = /EventAggregation\.dll\.bak/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string10 = /EventAggregation\.dll\.patched/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string11 = /EventAggregationPH\.dll/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string12 = /gabriellandau\/PPLFault/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string13 = /GMShellcode/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string14 = /GMShellcode\./ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string15 = /GMShellcode\\/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string16 = /GodFault\.exe/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string17 = /GodFault\\GodFault/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string18 = /HIJACK_DLL_PATH/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string19 = /lsass\.dmp/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string20 = /NoFault\\NoFault\./ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string21 = /PPLFault\./ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string22 = /PPLFault\.exe/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string23 = /PPLFault\-Localhost\-SMB\.ps1/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string24 = /PPLFaultPayload\.dll/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string25 = /PPLFaultTemp/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string26 = /smbserver\.py\s\-payload/ nocase ascii wide

    condition:
        any of them
}

rule chimera
{
    meta:
        description = "Detection patterns for the tool 'chimera' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chimera"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string1 = /.{0,1000}\schimera\.sh.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string2 = /.{0,1000}\s\-f\s.{0,1000}\.ps1\s\-l\s3\s\-o\s.{0,1000}\.ps1\s\-v\s\-t\spowershell.{0,1000}reverse.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string3 = /.{0,1000}\s\-f\sshells\/generic1\.ps1\s.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string4 = /.{0,1000}\s\-s\s.{0,1000}ascii.{0,1000}\s\-b\s.{0,1000}reverse.{0,1000}invoke\-expression.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string5 = /.{0,1000}\/Chimera\.git.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string6 = /.{0,1000}\/chimera\.sh.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string7 = /.{0,1000}\/opt\/chimera.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string8 = /.{0,1000}\/tmp\/chimera\.ps1.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string9 = /.{0,1000}\/tmp\/payload\.ps1.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string10 = /.{0,1000}\/tmp\/vt\-post\-.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string11 = /.{0,1000}\/tmp\/vt\-results\-.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string12 = /.{0,1000}Add\-RegBackdoor\.ps1.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string13 = /.{0,1000}Chimera\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string14 = /.{0,1000}Get\-WLAN\-Keys\.ps1.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string15 = /.{0,1000}Invoke\-PortScan.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string16 = /.{0,1000}Invoke\-PoshRatHttp.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string17 = /.{0,1000}Invoke\-PowerShellIcmp\.ps1.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string18 = /.{0,1000}Invoke\-PowerShellTcp\.ps1.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string19 = /.{0,1000}Invoke\-PowerShellTcpOneLine\.ps1.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string20 = /.{0,1000}Invoke\-PowerShellUdp\.ps1.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string21 = /.{0,1000}Invoke\-PowerShellUdpOneLine\.ps1.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string22 = /.{0,1000}null\-byte\.com\/bypass\-amsi.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string23 = /.{0,1000}powershell_reverse_shell\.ps1.{0,1000}/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string24 = /.{0,1000}tokyoneon\/Chimera.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

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
        $string1 = /\schimera\.sh/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string2 = /\s\-f\s.{0,1000}\.ps1\s\-l\s3\s\-o\s.{0,1000}\.ps1\s\-v\s\-t\spowershell.{0,1000}reverse/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string3 = /\s\-f\sshells\/generic1\.ps1\s/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string4 = /\s\-s\s.{0,1000}ascii.{0,1000}\s\-b\s.{0,1000}reverse.{0,1000}invoke\-expression/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string5 = /\/Chimera\.git/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string6 = /\/chimera\.sh/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string7 = /\/opt\/chimera/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string8 = /\/tmp\/chimera\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string9 = /\/tmp\/payload\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string10 = /\/tmp\/vt\-post\-.{0,1000}\.txt/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string11 = /\/tmp\/vt\-results\-.{0,1000}\.txt/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string12 = /Add\-RegBackdoor\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string13 = /Chimera\-master\.zip/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string14 = /Get\-WLAN\-Keys\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string15 = /Invoke\-PortScan/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string16 = /Invoke\-PoshRatHttp/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string17 = /Invoke\-PowerShellIcmp\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string18 = /Invoke\-PowerShellTcp\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string19 = /Invoke\-PowerShellTcpOneLine\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string20 = /Invoke\-PowerShellUdp\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string21 = /Invoke\-PowerShellUdpOneLine\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string22 = /null\-byte\.com\/bypass\-amsi/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string23 = /powershell_reverse_shell\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string24 = /tokyoneon\/Chimera/ nocase ascii wide

    condition:
        any of them
}

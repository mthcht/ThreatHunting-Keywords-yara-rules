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
        $string2 = /\s\-f\s.{0,100}\.ps1\s\-l\s3\s\-o\s.{0,100}\.ps1\s\-v\s\-t\spowershell.{0,100}reverse/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string3 = /\s\-f\sshells\/generic1\.ps1\s/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string4 = /\s\-s\s.{0,100}ascii.{0,100}\s\-b\s.{0,100}reverse.{0,100}invoke\-expression/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string5 = /\/Chimera\.git/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string6 = /\/chimera\.sh/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string7 = "/opt/chimera" nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string8 = /\/tmp\/chimera\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string9 = /\/tmp\/payload\.ps1/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string10 = /\/tmp\/vt\-post\-.{0,100}\.txt/ nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string11 = /\/tmp\/vt\-results\-.{0,100}\.txt/ nocase ascii wide
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
        $string15 = "Invoke-PortScan" nocase ascii wide
        // Description: Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.
        // Reference: https://github.com/tokyoneon/Chimera/
        $string16 = "Invoke-PoshRatHttp" nocase ascii wide
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
        $string24 = "tokyoneon/Chimera" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}

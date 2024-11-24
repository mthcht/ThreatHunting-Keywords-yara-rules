rule bypass_clm
{
    meta:
        description = "Detection patterns for the tool 'bypass-clm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bypass-clm"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string1 = "\"bypass-clm\"" nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string2 = /\/bypass\-clm\.exe/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string3 = /\/bypass\-clm\.git/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string4 = /\\bypass\-clm\.exe/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string5 = /\\bypass\-clm\.sln/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string6 = /\\bypass\-clm\\Program\.cs/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string7 = /\\Tasks\\bypass\-clm/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string8 = /\\Windows\\Microsoft\.NET\\.{0,100}\\InstallUtil\.exe\s\/logfile\=\s\/LogToConsole\=false\s\/U\s.{0,100}\:\\Windows\\Tasks\\/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string9 = "0b1a6a5a3e7a22a2f68a7b2b83b33117a63f0d6337dddb3d41b250a995210d79" nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string10 = "C8D738E6-8C30-4715-8AE5-6A8FBFE770A7" nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string11 = "calebstewart/bypass-clm" nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}

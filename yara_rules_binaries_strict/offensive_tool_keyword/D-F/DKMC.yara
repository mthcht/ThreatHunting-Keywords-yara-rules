rule DKMC
{
    meta:
        description = "Detection patterns for the tool 'DKMC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DKMC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string1 = /\/DKMC\.git/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string2 = /\/dkmc\.py/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string3 = /\/sc\-loader\.exe/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string4 = /\\dkmc\.py/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string5 = /\\sc\-loader\.exe/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string6 = /DKMC\-master\.zip/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string7 = /downloadshellcodebin\.c/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string8 = /downloadshellcodebin\.exe/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string9 = /exec\-sc\-rand\.ps1/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string10 = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBDAEYAVABUAEwAVgBrAEMALwB6AEUAMABPAFQAWQB" nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string11 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9ZoKnCHwsOdxe" nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string12 = "Module to generate shellcode out of raw metasploit shellcode file" nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string13 = "Mr-Un1k0d3r/DKMC" nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string14 = /python\sdkmc\.py/ nocase ascii wide
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

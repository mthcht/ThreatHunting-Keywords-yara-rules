rule prefetch_tool
{
    meta:
        description = "Detection patterns for the tool 'prefetch-tool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "prefetch-tool"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string1 = /\/prefetch\-tool\.git/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string2 = /\\prefetch_leak\.h/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string3 = /\\prefetch_tool\.sln/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string4 = /\\prefetch_tool\.vcxproj/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string5 = /82ac960f25131540ae230b2bac0f003ffc8edc8a05382d8831ff8e8ebf30996d/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string6 = /8aba74be7acef3c84cef0163411298aa994872347a4ac84cc0a0d19ddf0eb65c/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string7 = /A46C9A13\-145E\-42C0\-8CA6\-CC920BF1D9F1/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string8 = /exploits\-forsale\/prefetch\-tool/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string9 = /include\s\\"prefetch_leak\.h\\"/ nocase ascii wide
        // Description: Windows KASLR bypass using prefetch side-channel CVE-2024-21345 exploitation
        // Reference: https://github.com/exploits-forsale/prefetch-tool
        $string10 = /lallousz\-x86\@yahoo\.com/ nocase ascii wide
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

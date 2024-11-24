rule IHxExec
{
    meta:
        description = "Detection patterns for the tool 'IHxExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IHxExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string1 = /\/IHxExec\.exe/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string2 = /\/IHxExec\.git/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string3 = /\/IHxExec\-main\.zip/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string4 = /\\IHxExec\.cpp/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string5 = /\\IHxExec\.exe/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string6 = /\\IHxExec\.vcxproj/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string7 = /\\IHxExec\-main/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string8 = "165a010438ef6f3b9d8dfbb47e486740e5d8235e77d28efb7b7c1b93654f71b4" nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string9 = "c0ac59bed2e0208db150069c4d943a73036d03271754075029bc2e41f24bb303" nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string10 = "CICADA8-Research/IHxExec" nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string11 = "d5092358-f3ab-4712-9c7f-d9ec4390193c" nocase ascii wide
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

rule PrintNightmare
{
    meta:
        description = "Detection patterns for the tool 'PrintNightmare' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrintNightmare"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string1 = " = \"NeverGonnaRunAroundAndDesertYou\"" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/calebstewart/CVE-2021-1675
        $string2 = " Invoke-Nightmare" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string3 = " namespace SharpPrintNightmare" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/calebstewart/CVE-2021-1675
        $string4 = /\$DriverName\s\=\s\\"Totally\sNot\sMalicious\\"/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string5 = /\/CVE\-2021\-1675\.git/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string6 = /\/PrintNightmare\.git/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/calebstewart/CVE-2021-1675
        $string7 = /\[\+\]\sExploit\sCompleted/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string8 = /\\PrintNightmare\./ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string9 = "0CD16C7B-2A65-44E5-AB74-843BD23241D3" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string10 = "0eec76148fd7a3b1eb54d3fa71c30b5370d410e1eb81231ff0e9e66de3598aea" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string11 = "290083a0a3dac6b3c05ab3e01fb5cdfb128c0175914f1fe64cdb1a5e247d43f0" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string12 = "2daeb177f86c873780c59e59fa8c424e45aea199bf5fb3e935310b043d41787f" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string13 = "4709b94c38800c9a400aeee54241b107b8fd597f34e3283949a18537f2ae04a7" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string14 = "55b8235e7a749bac3ce56589298727a4314ea2e2ac9ba706b183ca3781cc16f8" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string15 = "5FEB114B-49EC-4652-B29E-8CB5E752EC3E" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/calebstewart/CVE-2021-1675
        $string16 = "5FEB114B-49EC-4652-B29E-8CB5E752EC3E" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string17 = "b8f5ed1345cb6970bd21babe5a58d45e035a9ecd04b961b995b2a03023beea87" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string18 = "BBFBAF1D-A01E-4615-A208-786147320C20" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/calebstewart/CVE-2021-1675
        $string19 = "calebstewart/CVE-2021-1675" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string20 = "cube0x0/CVE-2021-1675" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/calebstewart/CVE-2021-1675
        $string21 = /CVE\-2021\-1675\.ps1/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string22 = /CVE\-2021\-1675\.py/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string23 = "D30C9D6B-1F45-47BD-825B-389FE8CC9069" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/calebstewart/CVE-2021-1675
        $string24 = "Invoke-Nightmare " nocase ascii wide
        // Description: mimikatz printnightmare exploitation
        // Reference: N/A
        $string25 = "misc::printnightmare" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string26 = "outflanknl/PrintNightmare" nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string27 = /PrintNightmare\.dll/ nocase ascii wide
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/cube0x0/CVE-2021-1675
        $string28 = /SharpPrintNightmare\.exe/ nocase ascii wide
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

rule Executable_Files
{
    meta:
        description = "Detection patterns for the tool 'Executable_Files' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Executable_Files"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string1 = /\sexfiltrate\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string2 = /\/Executable_Files\.git/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string3 = /\/exfiltrate\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string4 = /\/Hades\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string5 = /\/Rubeus\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string6 = "/XOR_b64_encrypted/" nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string7 = /\\exfiltrate\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string8 = /\\Hades\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string9 = /\\Rubeus\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string10 = /\\XOR_b64_encrypted\\/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string11 = /\\xorencrypt\.py/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string12 = /badger_x64_stealth_rtl\.txt/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string13 = /cpp_test_payload\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string14 = /Executable_Files\-main\.zip/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string15 = /exfiltrate_via_post\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string16 = /HelloReflectionWorld\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string17 = /https_revshell\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string18 = /mimikatz\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string19 = /mssgbox_shellcode_arranged_x64\.b64/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string20 = /mssgbox_shellcode_exitfunc_thread_x64\.bin/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string21 = /mssgbox_shellcode_x64\.b64/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string22 = /mssgbox_shellcode_x64\.bin/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string23 = /mssgbox_shellcode_x64\.bin/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string24 = /mssgbox_shellcode_x64_with_hexsymbol\.txt/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string25 = /mssgbox_shellcode_x64_without_hexsymbol\.txt/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string26 = /RegistryTinker\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string27 = "rev_kali_192_168_0_110_1234" nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string28 = "reveng007/Executable_Files" nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string29 = /Rubeus\.exe\s/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string30 = /SafetyKatz\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string31 = /win_rev_http\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string32 = /win_rev_https\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string33 = /win_rev_tcp\.exe/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string34 = /XOR_b64_encrypted.{0,100}covenant\.txt/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string35 = /XOR_b64_encrypted.{0,100}covenant2\.txt/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string36 = /XOR_b64_encrypted.{0,100}havoc\.txt/ nocase ascii wide
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

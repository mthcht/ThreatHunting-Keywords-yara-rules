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
        $string1 = /.{0,1000}\sexfiltrate\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string2 = /.{0,1000}\/Executable_Files\.git.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string3 = /.{0,1000}\/exfiltrate\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string4 = /.{0,1000}\/Hades\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string5 = /.{0,1000}\/Rubeus\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string6 = /.{0,1000}\/XOR_b64_encrypted\/.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string7 = /.{0,1000}\\exfiltrate\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string8 = /.{0,1000}\\Hades\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string9 = /.{0,1000}\\Rubeus\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string10 = /.{0,1000}\\XOR_b64_encrypted\\.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string11 = /.{0,1000}\\xorencrypt\.py.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string12 = /.{0,1000}badger_x64_stealth_rtl\.txt.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string13 = /.{0,1000}cpp_test_payload\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string14 = /.{0,1000}Executable_Files\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string15 = /.{0,1000}exfiltrate_via_post\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string16 = /.{0,1000}HelloReflectionWorld\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string17 = /.{0,1000}https_revshell\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string18 = /.{0,1000}mimikatz\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string19 = /.{0,1000}mssgbox_shellcode_arranged_x64\.b64.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string20 = /.{0,1000}mssgbox_shellcode_exitfunc_thread_x64\.bin.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string21 = /.{0,1000}mssgbox_shellcode_x64\.b64.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string22 = /.{0,1000}mssgbox_shellcode_x64\.bin.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string23 = /.{0,1000}mssgbox_shellcode_x64\.bin.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string24 = /.{0,1000}mssgbox_shellcode_x64_with_hexsymbol\.txt.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string25 = /.{0,1000}mssgbox_shellcode_x64_without_hexsymbol\.txt.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string26 = /.{0,1000}RegistryTinker\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string27 = /.{0,1000}rev_kali_192_168_0_110_1234.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string28 = /.{0,1000}reveng007\/Executable_Files.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string29 = /.{0,1000}Rubeus\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string30 = /.{0,1000}SafetyKatz\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string31 = /.{0,1000}win_rev_http\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string32 = /.{0,1000}win_rev_https\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string33 = /.{0,1000}win_rev_tcp\.exe.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string34 = /.{0,1000}XOR_b64_encrypted.{0,1000}covenant\.txt.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string35 = /.{0,1000}XOR_b64_encrypted.{0,1000}covenant2\.txt.{0,1000}/ nocase ascii wide
        // Description: Database for custom made as well as publicly available stage-2 or beacons or stageless payloads used by loaders/stage-1/stagers or for further usage of C2 as well
        // Reference: https://github.com/reveng007/Executable_Files
        $string36 = /.{0,1000}XOR_b64_encrypted.{0,1000}havoc\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

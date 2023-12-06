rule ReflectiveNtdll
{
    meta:
        description = "Detection patterns for the tool 'ReflectiveNtdll' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ReflectiveNtdll"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string1 = /\/enc_shellcode\.bin/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string2 = /\/enc_shellcode\.h/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string3 = /\/ReflectiveNtdll\.git/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string4 = /\\1\.Encrypt_shellcode/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string5 = /\\enc_shellcode\.bin/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string6 = /\\enc_shellcode\.h/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string7 = /\\implant\.exe\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string8 = /POC1.{0,1000}implant\.cpp/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string9 = /POC2.{0,1000}implant\.cpp/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string10 = /ReflectiveNtdll\-main/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string11 = /reveng007\/ReflectiveNtdll/ nocase ascii wide

    condition:
        any of them
}

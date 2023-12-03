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
        $string1 = /.{0,1000}\/enc_shellcode\.bin.{0,1000}/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string2 = /.{0,1000}\/enc_shellcode\.h.{0,1000}/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string3 = /.{0,1000}\/ReflectiveNtdll\.git.{0,1000}/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string4 = /.{0,1000}\\1\.Encrypt_shellcode.{0,1000}/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string5 = /.{0,1000}\\enc_shellcode\.bin.{0,1000}/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string6 = /.{0,1000}\\enc_shellcode\.h.{0,1000}/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string7 = /.{0,1000}\\implant\.exe\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string8 = /.{0,1000}POC1.{0,1000}implant\.cpp.{0,1000}/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string9 = /.{0,1000}POC2.{0,1000}implant\.cpp.{0,1000}/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string10 = /.{0,1000}ReflectiveNtdll\-main.{0,1000}/ nocase ascii wide
        // Description: A Dropper POC with a focus on aiding in EDR evasion - NTDLL Unhooking followed by loading ntdll in-memory which is present as shellcode
        // Reference: https://github.com/reveng007/ReflectiveNtdll
        $string11 = /.{0,1000}reveng007\/ReflectiveNtdll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

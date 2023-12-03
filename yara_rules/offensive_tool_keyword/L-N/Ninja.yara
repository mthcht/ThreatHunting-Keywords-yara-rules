rule Ninja
{
    meta:
        description = "Detection patterns for the tool 'Ninja' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ninja"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string1 = /.{0,1000}\sNinja\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string2 = /.{0,1000}\sstart_campaign\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string3 = /.{0,1000}\.\/Ninja\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string4 = /.{0,1000}\/ahmedkhlief\/Ninja\/.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string5 = /.{0,1000}\/ninja\.crt.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string6 = /.{0,1000}\/Ninja\.git.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string7 = /.{0,1000}\/ninja\.key.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string8 = /.{0,1000}\/Ninja\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string9 = /.{0,1000}\/opt\/Ninja\/.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string10 = /.{0,1000}\/payload2\.ps1.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string11 = /.{0,1000}\/start_campaign\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string12 = /.{0,1000}\/webshell\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string13 = /.{0,1000}\\Ninja\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string14 = /.{0,1000}\\start_campaign\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string15 = /.{0,1000}agents\/Follina\-2.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string16 = /.{0,1000}ahmedkhlief\/Ninja.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string17 = /.{0,1000}ahmedkhlief\/Ninja.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string18 = /.{0,1000}AMSI_Bypass\.ps1.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string19 = /.{0,1000}ASBBypass\.ps1.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string20 = /.{0,1000}b64stager.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string21 = /.{0,1000}\'C2Default\'.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string22 = /.{0,1000}c2\-logs\.txt.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string23 = /.{0,1000}cmd_shellcodex64\..{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string24 = /.{0,1000}cmd_shellcodex86\..{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string25 = /.{0,1000}create\-aws\-instance\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string26 = /.{0,1000}donut\-shellcode.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string27 = /.{0,1000}dropper_cs\.exe.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string28 = /.{0,1000}Find\-PSServiceAccounts\.ps1.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string29 = /.{0,1000}Follina\.Ninja.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string30 = /.{0,1000}Follina\/follina\.html.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string31 = /.{0,1000}Follina\/Follinadoc.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string32 = /.{0,1000}get_beacon\(.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string33 = /.{0,1000}Invoke\-Kerberoast.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string34 = /.{0,1000}Invoke\-Kerberoast\.ps1.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string35 = /.{0,1000}Invoke\-Mimikatz\-old.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string36 = /.{0,1000}Invoke\-WMIExec.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string37 = /.{0,1000}Kerberoast\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string38 = /.{0,1000}Ninja\sc2.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string39 = /.{0,1000}ninjac2.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string40 = /.{0,1000}Obfuscate\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string41 = /.{0,1000}payloads\/Follina.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string42 = /.{0,1000}payloads\/Powershell.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string43 = /.{0,1000}payloads\/shellcodes.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string44 = /.{0,1000}python3\sNinja\.py.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string45 = /.{0,1000}safetydump\.ninja.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string46 = /.{0,1000}safetydump\.ninja.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string47 = /.{0,1000}SharpHound\.ps1.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string48 = /.{0,1000}simple_dropper\.ninja.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string49 = /.{0,1000}webshell_execute.{0,1000}/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string50 = /python3\sstart_campaign\.py/ nocase ascii wide

    condition:
        any of them
}

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
        $string1 = /\sNinja\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string2 = /\sstart_campaign\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string3 = /\.\/Ninja\.py/
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string4 = "/ahmedkhlief/Ninja/" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string5 = /\/ninja\.crt/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string6 = /\/Ninja\.git/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string7 = /\/ninja\.key/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string8 = /\/Ninja\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string9 = "/opt/Ninja/" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string10 = /\/payload2\.ps1/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string11 = /\/start_campaign\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string12 = /\/webshell\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string13 = /\\Ninja\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string14 = /\\start_campaign\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string15 = "agents/Follina-2" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string16 = "ahmedkhlief/Ninja" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string17 = /AMSI_Bypass\.ps1/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string18 = /ASBBypass\.ps1/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string19 = "b64stager" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string20 = "'C2Default'" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string21 = /c2\-logs\.txt/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string22 = /cmd_shellcodex64\./ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string23 = /cmd_shellcodex86\./ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string24 = /create\-aws\-instance\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string25 = "donut-shellcode" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string26 = /dropper_cs\.exe/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string27 = /Find\-PSServiceAccounts\.ps1/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string28 = /Follina\.Ninja/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string29 = /Follina\/follina\.html/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string30 = "Follina/Follinadoc" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string31 = /get_beacon\(/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string32 = "Invoke-Kerberoast" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string33 = /Invoke\-Kerberoast\.ps1/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string34 = "Invoke-Mimikatz-old" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string35 = "Invoke-WMIExec" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string36 = /Kerberoast\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string37 = "Ninja c2" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string38 = "ninjac2" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string39 = /Obfuscate\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string40 = "payloads/Follina" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string41 = "payloads/Powershell" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string42 = "payloads/shellcodes" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string43 = /python3\sNinja\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string44 = /python3\sstart_campaign\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string45 = /safetydump\.ninja/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string46 = /safetydump\.ninja/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string47 = /SharpHound\.ps1/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string48 = /simple_dropper\.ninja/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string49 = "webshell_execute" nocase ascii wide

    condition:
        any of them
}

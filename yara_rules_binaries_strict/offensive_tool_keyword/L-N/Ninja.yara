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
        $string17 = "ahmedkhlief/Ninja" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string18 = /AMSI_Bypass\.ps1/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string19 = /ASBBypass\.ps1/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string20 = "b64stager" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string21 = "'C2Default'" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string22 = /c2\-logs\.txt/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string23 = /cmd_shellcodex64\./ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string24 = /cmd_shellcodex86\./ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string25 = /create\-aws\-instance\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string26 = "donut-shellcode" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string27 = /dropper_cs\.exe/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string28 = /Find\-PSServiceAccounts\.ps1/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string29 = /Follina\.Ninja/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string30 = /Follina\/follina\.html/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string31 = "Follina/Follinadoc" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string32 = /get_beacon\(/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string33 = "Invoke-Kerberoast" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string34 = /Invoke\-Kerberoast\.ps1/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string35 = "Invoke-Mimikatz-old" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string36 = "Invoke-WMIExec" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string37 = /Kerberoast\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string38 = "Ninja c2" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string39 = "ninjac2" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string40 = /Obfuscate\.py/ nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string41 = "payloads/Follina" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string42 = "payloads/Powershell" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string43 = "payloads/shellcodes" nocase ascii wide
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string44 = /python3\sNinja\.py/ nocase ascii wide
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
        // Description: Open source C2 server created for stealth red team operations
        // Reference: https://github.com/ahmedkhlief/Ninja
        $string50 = /python3\sstart_campaign\.py/ nocase ascii wide
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

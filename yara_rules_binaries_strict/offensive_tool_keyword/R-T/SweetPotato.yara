rule SweetPotato
{
    meta:
        description = "Detection patterns for the tool 'SweetPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SweetPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string1 = " --exploit=DCOM" nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string2 = " --exploit=DCOM" nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string3 = " --exploit=EfsRpc" nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string4 = " --exploit=PrintSpoofer" nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string5 = " --exploit=WinRM" nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string6 = /\sSweetpotato\.exe/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string7 = /\/Sweetpotato\.exe/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string8 = /\/SweetPotato\.git/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string9 = /\/SweetPotato\-master\.zip/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string10 = /\[\+\]\sAttempting\sDCOM\sNTLM\srelaying\swith\sCLSID/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string11 = /\[\+\]\sAttempting\sNP\simpersonation\susing\smethod\sEfsRpc\sto\slaunch\s/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string12 = /\[\+\]\sAttempting\sNP\simpersonation\susing\smethod\sPrintSpoofer\sto\slaunch\s/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string13 = /\[\+\]\sServer\sconnected\sto\sour\sevil\sRPC\spipe/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string14 = /\[\+\]\sTriggering\sname\spipe\saccess\son\sevil\sPIPE\s/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string15 = /\\Sweetpotato\.exe/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string16 = /\\SweetPotato\\Program\.cs/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string17 = /\\SweetPotato\-master\.zip/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string18 = "1BF9C10F-6F89-4520-9D2E-AAF17D17BA5E" nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string19 = "8f2a1d66e0a532a030da8e0e646f866ea91ee987ffb33b36d95f64a0538a3e20" nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string20 = "CCob/SweetPotato" nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string21 = /PotatoAPI\.Mode\.DCOMRemote/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string22 = "Remote Potato by @decoder_it and @splinter_code" nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string23 = "SweetPotato by @_EthicalChaos_" nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string24 = "Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery" nocase ascii wide
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

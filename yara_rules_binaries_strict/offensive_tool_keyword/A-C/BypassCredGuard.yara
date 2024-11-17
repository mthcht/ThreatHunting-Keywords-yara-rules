rule BypassCredGuard
{
    meta:
        description = "Detection patterns for the tool 'BypassCredGuard' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BypassCredGuard"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string1 = /\sBypassCredGuard\.exe/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string2 = /\/BypassCredGuard\.cpp/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string3 = /\/BypassCredGuard\.exe/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string4 = /\/BypassCredGuard\.git/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string5 = /\[\-\]\sFailed\sto\sReadProcessMemory\sfor\sg_fParameter_UseLogonCredential/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string6 = /\[\-\]\sFailed\sto\sReadProcessMemory\sfor\sg_IsCredGuardEnabled/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string7 = /\[\-\]\sFailed\sto\sWriteProcessMemory\sfor\sg_fParameter_UseLogonCredential/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string8 = /\[\-\]\sFailed\sto\sWriteProcessMemory\sfor\sg_IsCredGuardEnabled\./ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string9 = /\\BypassCredGuard\.cpp/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string10 = /\\BypassCredGuard\.exe/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string11 = /\\BypassCredGuard\.log/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string12 = /\\bypasscredguard\.pdb/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string13 = /2a46df8322062f52a20c78eb93d7b068b61037db2ce48edcb9f8beda43dd8ede/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string14 = /3422b5b6a7d4b662727baf8a4615c884a4295b71b8d0412130415b737a4cd216/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string15 = /5b55d8a0b50b89156ef7d09cffede9385fdad53301c16f2570a1888e7ee1cdf7/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string16 = /9b361496733f31eed59d74b17f7eab74e3175f69e14fb24f9dbde5a359c2c39b/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string17 = /BypassCredGuard\/zipball/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string18 = /BypassCredGuard\-master/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string19 = /F1527C49\-CA1F\-4994\-BB9D\-E20DD2C607FD/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string20 = /wh0amitz\/BypassCredGuard/ nocase ascii wide
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

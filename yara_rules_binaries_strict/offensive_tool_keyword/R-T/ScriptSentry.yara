rule ScriptSentry
{
    meta:
        description = "Detection patterns for the tool 'ScriptSentry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScriptSentry"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string1 = /\/ScriptSentry\.git/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string2 = /\/ScriptSentry\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string3 = /\/ScriptSentry\.psd1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string4 = /\/ScriptSentry\.psm1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string5 = /\\ScriptSentry\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string6 = /\\ScriptSentry\.psd1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string7 = /\\ScriptSentry\.psm1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string8 = /\\ScriptSentry\.txt/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string9 = "e1cd2b55-3b4f-41bd-a168-40db41e34349" nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string10 = /Find\-AdminLogonScripts\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string11 = "Find-LogonScriptCredentials -LogonScripts" nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string12 = /Find\-LogonScriptCredentials\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string13 = /Find\-UnsafeLogonScriptPermissions\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string14 = "Find-UnsafeUNCPermissions -UNCScripts" nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string15 = /Find\-UnsafeUNCPermissions\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string16 = /Get\-DomainAdmins\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string17 = "Invoke-ScriptSentry" nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string18 = /ScriptSentry\-main\.zip/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string19 = "techspence/ScriptSentry" nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}

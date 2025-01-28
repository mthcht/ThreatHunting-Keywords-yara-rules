rule reaper
{
    meta:
        description = "Detection patterns for the tool 'reaper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reaper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string1 = /\/Reaper\.git/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string2 = /\/Reaper\/Reaper\.cpp/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string3 = /\/ReaperX64\.zip/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string4 = /\\Reaper\\Reaper\.cpp/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string5 = /\\Reaper\-main\\.{0,100}\.sys/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string6 = /\\Temp\\Reaper\.exe/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string7 = "30f7ba049eab00673ae6b247199ec4f6af533d9ba46482159668fd23f484bdc6" nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string8 = "526f652d4d9e20a19374817eac75b914b75f3bfaecc16b65f979e5758ea62476" nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string9 = "c725919e6357126d512c638f993cf572112f323da359645e4088f789eb4c7b8c" nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string10 = "CB561720-0175-49D9-A114-FE3489C53661" nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string11 = /github\.com\/.{0,100}Reaper\.exe/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string12 = "MrEmpy/Reaper" nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string13 = /Reaper\.exe\skp\s/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string14 = /Reaper\.exe\ssp\s/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string15 = /Reaper\-main\.zip/ nocase ascii wide
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

rule DumpAADSyncCreds
{
    meta:
        description = "Detection patterns for the tool 'DumpAADSyncCreds' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpAADSyncCreds"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // Reference: https://github.com/Hagrid29/DumpAADSyncCreds
        $string1 = /\/DumpAADSyncCreds\.git/ nocase ascii wide
        // Description: C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // Reference: https://github.com/Hagrid29/DumpAADSyncCreds
        $string2 = /\[\+\]\sObtained\sADSync\sservice\saccount\stoken\sfrom\smiiserver\sprocess/ nocase ascii wide
        // Description: C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // Reference: https://github.com/Hagrid29/DumpAADSyncCreds
        $string3 = /95A40D7C\-F3F7\-4C45\-8C5A\-D384DE50B6C9/ nocase ascii wide
        // Description: C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // Reference: https://github.com/Hagrid29/DumpAADSyncCreds
        $string4 = /ADSync\spasswords\scan\sbe\sread\sor\smodified\sas\slocal\sadministrator\sonly\sfor\sADSync\sversion\s/ nocase ascii wide
        // Description: C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // Reference: https://github.com/Hagrid29/DumpAADSyncCreds
        $string5 = /Dump\sAAD\sconnect\saccount\scredential\sin\scurrent\scontext/ nocase ascii wide
        // Description: C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // Reference: https://github.com/Hagrid29/DumpAADSyncCreds
        $string6 = /DumpAADSyncCreds\.csproj/ nocase ascii wide
        // Description: C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // Reference: https://github.com/Hagrid29/DumpAADSyncCreds
        $string7 = /DumpAADSyncCreds\.exe/ nocase ascii wide
        // Description: C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // Reference: https://github.com/Hagrid29/DumpAADSyncCreds
        $string8 = /DumpAADSyncCreds\.sln/ nocase ascii wide
        // Description: C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // Reference: https://github.com/Hagrid29/DumpAADSyncCreds
        $string9 = /e6e05a88178633c271919ae5ea4c9633991774e2fd345ffe3052c209e2ef31d5/ nocase ascii wide
        // Description: C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // Reference: https://github.com/Hagrid29/DumpAADSyncCreds
        $string10 = /Hagrid29\/DumpAADSyncCreds/ nocase ascii wide
        // Description: C# implementation of Get-AADIntSyncCredentials from AADInternals which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.
        // Reference: https://github.com/Hagrid29/DumpAADSyncCreds
        $string11 = /P\@ss4Hagrid29/ nocase ascii wide
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

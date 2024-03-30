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

    condition:
        any of them
}

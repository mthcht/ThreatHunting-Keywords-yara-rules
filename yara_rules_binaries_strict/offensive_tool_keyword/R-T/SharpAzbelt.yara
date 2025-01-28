rule SharpAzbelt
{
    meta:
        description = "Detection patterns for the tool 'SharpAzbelt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAzbelt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string1 = /\/SharpAzbelt\.git/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string2 = /\[\!\]\s\s\s\sFailed\sto\senumerate\sCredman\:/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string3 = /\[i\]\sAAD\sJoin\:.{0,100}enumerate/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string4 = /\[i\]\sCredman\:.{0,100}Credential\sBlob\sDecrypted/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string5 = /\\SharpAzbelt\.csproj/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string6 = /\\SharpAzbelt\.exe/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string7 = /\\SharpAzbelt\.sln/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string8 = "57D4D4F4-F083-47A3-AE33-AE2500ABA3B6" nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string9 = /ParseMSALCache.{0,100}\.azure\\msal_token_cache\.bin/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string10 = /ParseMSALCache.{0,100}Appdata\\Local\\\.IdentityService\\msal\.cache/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string11 = "redskal/SharpAzbelt" nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string12 = "SharpAzbelt-main" nocase ascii wide
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

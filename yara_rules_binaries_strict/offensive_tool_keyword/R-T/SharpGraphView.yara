rule SharpGraphView
{
    meta:
        description = "Detection patterns for the tool 'SharpGraphView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGraphView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string1 = " Invoke-CertToAccessToken -tenant " nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string2 = /\/SharpGraphView\.git/ nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string3 = /\\SharpGraphView\.sln/ nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string4 = /\\sharpgraphview\\/ nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string5 = ">SharpGraphView<" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string6 = "2beff60039dfd82bd092bae6e69a92ed04cdcf7cfe597868bb161dbc15c3de73" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string7 = "3922246663d030813506516c147f8281d8c81f1cdc1153238643f580b52093d7" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string8 = "64d0026295c3c887bbcb256967aae006f4df254a2bc9418f9a1dc30fd6115ee1" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string9 = "825E2088-EC7C-4AB0-852A-4F1FEF178E37" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string10 = "mlcsec/SharpGraphView" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string11 = /SharpGraph\.exe\sGet\-UserChatMessages\s\-id\s/ nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string12 = /SharpGraph\.exe\sList\-ChatMessages\s/ nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string13 = /SharpGraphView\.exe/ nocase ascii wide
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

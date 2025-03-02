rule AppProxyC2
{
    meta:
        description = "Detection patterns for the tool 'AppProxyC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AppProxyC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string1 = /\/AppProxyC2\.git/ nocase ascii wide
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string2 = /\\AppProxyC2\./ nocase ascii wide
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string3 = "00de5c3931a567291bf9893e217004b8d6d7fd834798e80a60c7e97ac9d1f346" nocase ascii wide
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string4 = "018cedf55d51bc510037225619f98f49b5138d842f3d375e1cd880bb102e047e" nocase ascii wide
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string5 = "1A99EBED-6E53-469F-88B7-F4C3D2C96B07" nocase ascii wide
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string6 = "4d76a28ba8830185fde42e139a27d7bd8197f33810b06fcfb7980c8ddba589cf" nocase ascii wide
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string7 = "57c7c32de040ad8525da2c58585fe1c0e7bfd848b81308015a055e81d8cb5492" nocase ascii wide
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string8 = "8443F171-603C-499C-B6A6-F4F6910FD1D9" nocase ascii wide
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string9 = "App Proxy ExternalC2 POC by @_xpn_" nocase ascii wide
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string10 = /AppProxyC2CertificateCreator\.exe/ nocase ascii wide
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string11 = "d97f43bd7924dfd635d36d53e2bf95c850f36bf2210d159aa602b87162aceaa6" nocase ascii wide
        // Description: simple POC to show how to tunnel traffic through Azure Application Proxy
        // Reference: https://github.com/xpn/AppProxyC2
        $string12 = "xpn/AppProxyC2" nocase ascii wide
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

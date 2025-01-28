rule ROADtoken
{
    meta:
        description = "Detection patterns for the tool 'ROADtoken' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ROADtoken"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string1 = /\/ROADToken\.exe/ nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string2 = /\/ROADtoken\.git/ nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string3 = /\\ROADToken\.csproj/ nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string4 = /\\ROADToken\.exe/ nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string5 = /\\ROADToken\.sln/ nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string6 = /\>ROADToken\.exe\</ nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string7 = ">ROADToken<" nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string8 = "018BD6D4-9019-42FD-8D3A-831B23B47CB2" nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string9 = "0ed9e5a905e2ec8e15e331561cc665ad5b5c5fe3ec34ffacea54b6ee51244b5c" nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string10 = "20144d177f7af4b900fddf4466327737bb72bf30c450a4e6a577f0efc6449647" nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string11 = "484f12b93ca5f088c3a0db9f31106c2fc855642292fc867a512df8f6a8826d09" nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string12 = "746726f4bb20bc303db072b0496a69e91b409285bad1c5507d1969ef19d27380" nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string13 = "dirkjanm/ROADtoken" nocase ascii wide
        // Description: Abusing Azure AD SSO with the Primary Refresh Token - ROADtoken is a tool that uses the BrowserCore.exe binary to obtain a cookie that can be used with SSO and Azure AD
        // Reference: https://github.com/dirkjanm/ROADtoken
        $string14 = /https\:\/\/dirkjanm\.io\/abusing\-azure\-ad\-sso\-with\-the\-primary\-refresh\-token\// nocase ascii wide
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

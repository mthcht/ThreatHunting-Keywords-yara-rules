rule ShareAudit
{
    meta:
        description = "Detection patterns for the tool 'ShareAudit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShareAudit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string1 = /\/shareaudit\.exe/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string2 = /\/ShareAudit\.git/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string3 = "/ShareAudit/releases/download/" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string4 = /\\2023.{0,100}\.shareaudit/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string5 = /\\2024.{0,100}\.shareaudit/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string6 = /\\2025.{0,100}\.shareaudit/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string7 = /\\shareaudit\.exe/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string8 = /\\ShareAudit\.sln/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string9 = /\>Dionach\.ShareAudit\</ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string10 = /\>ShareAudit\.exe\</ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string11 = "0316bec32da4114fafd515553b7e928c1a62efebbe5ec57842d17b63beed58df" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string12 = "09407d2e3ac7d6af13c407d17ec8e51b6d1b1d8271df65ebd0b3ffbab420b2fe" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string13 = "1D1B59D9-10AF-40FE-BE99-578C09DB7A2A" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string14 = "1DFC488D-E104-4F35-98DA-F23BF6D3F9DC" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string15 = "28CF3837-FF58-463B-AF81-E6B0039DE55F" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string16 = "360cf81e70e3f8cbdbb442c972896794f49c72515b1bc1699b2d25c8a37e4bfd" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string17 = "76a9aef76f34f01a3f20cfb3a72fc17340840d07b3acb74e50a9cb1bd0ecc840" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string18 = "7a96ab7f25001fee0cfc74b67cc4d97016b073e0d924dc26a0bd90028825fbbd" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string19 = "8425D05F-F3F4-4132-9BE1-BED752685333" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string20 = "b665b3db7a4ae240cf1e9526a11677bd25bd0f943bee7fd9a2df56f16a9a460f" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string21 = "cb21ae1cd69be5a97dd4b3e67779100a58f86761ecd83624e5645945a8df0c59" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string22 = "cbe090ee5a7210e39968ed958acbecdf0251eceb8e7b0f4acec6efb21e63025f" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string23 = "d19415ba5aa5fcb87bcf4c3185e5ccaf0da896ed49495ce5297d89e8ad7988e4" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string24 = "d4cfe09288719470c75a0e7b7054dd567d3255d1a331926ef8d5c91ea692a3d0" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string25 = /Dionach\.ShareAudit\.Model\.dll/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string26 = /Dionach\.ShareAudit\.Modules\.Services\.Interop\.dll/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string27 = "dionach/ShareAudit" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string28 = "F5BFA34B-3CDE-4C77-9162-96666303FDEA" nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string29 = /Select\-String\s\-Path\s\.\\nmap_smb\.gnmap\s\-Pattern\s.{0,100}open.{0,100}\|\sforeach\s\{\secho\s\$_\.tostring\(\)\.split\(\)\[1\]\s\}\s\>\s/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string30 = /ShareAudit\sis\sa\stool\sfor\sauditing\snetwork\sshare\spermissions\sin\san\sActive\sDirectory\senvironment\.\sTo\sget\sstarted\seither\screate\sa\snew\sproject\sor\sload\san\sexisting\sproject\.\sFor\smore\sinformation\sregarding\show\sto\saudit\syour\snetwork\sshares/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string31 = /ShareAudit\.v3\.0\.0\.exe/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string32 = /ShareAudit\.v3\.0\.1\.exe/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string33 = /ShareAudit\.v3\.0\.2\.exe/ nocase ascii wide
        // Description: A tool for auditing network shares in an Active Directory environment
        // Reference: https://github.com/dionach/ShareAudit
        $string34 = /ShareAudit\-master\.zip/ nocase ascii wide
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

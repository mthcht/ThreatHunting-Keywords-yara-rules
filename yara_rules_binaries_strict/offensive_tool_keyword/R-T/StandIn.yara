rule StandIn
{
    meta:
        description = "Detection patterns for the tool 'StandIn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StandIn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string1 = /\s\-\-adcs\s\-\-filter\s.{0,100}\s\-\-ntaccount\s.{0,100}\s\-\-enroll\s/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string2 = /\s\-\-asrep\s\-\-domain\s.{0,100}\s\-\-user\s.{0,100}\s\-\-pass\s/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string3 = /\s\-\-ldap\sservicePrincipalName\=.{0,100}\s\-\-domain\s.{0,100}\s\-\-user\s.{0,100}\s\-\-pass\s/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string4 = /\s\-\-passnotreq\s\-\-domain\s.{0,100}\s\-\-user\s.{0,100}\s\-\-pass\s/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string5 = /\.exe\s\-\-asrep/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string6 = /\.exe\s\-\-gpo\s\-\-filter\sadmin\s\-\-domain/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string7 = /\.exe\s\-\-spn\s\-\-domain\s.{0,100}\s\-\-user\s.{0,100}\s\-\-pass\s/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string8 = /\/StandIn\.exe/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string9 = /\/StandIn\.git/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string10 = /\/StandIn_Net35\.exe/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string11 = /\/StandIn_Net45\.exe\s/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string12 = /\/StandIn\-1\.3\.zip/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string13 = /\@\\"\s\(\s_\/_\s\s\s_\/\/\s\s\s\~b33f\\"/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string14 = /\[\!\]\sFailed\sto\senumerate\sADCS\sdata\./ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string15 = /\[\+\]\sSID\sadded\sto\smsDS\-AllowedToActOnBehalfOfOtherIdentity/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string16 = /\\CultesDesGoules\.txt/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string17 = /\\nMethodNamespace\=StandIn/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string18 = /\\StandIn\s\-\-/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string19 = /\\StandIn\.exe/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string20 = /\\StandIn\.pdb/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string21 = /\\StandIn\\hStandIn\.cs/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string22 = /\\StandIn\\Program\.cs/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string23 = /\\StandIn_Net35\.exe/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string24 = /\\StandIn_Net45\.exe\s/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string25 = /\\StandIn\-1\.3\.zip/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string26 = "01C142BA-7AF1-48D6-B185-81147A2F7DB7" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string27 = "24C53132B594B77D2109CAEE3E276EA4603EEF32BFECD5121746DB58258C50F7" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string28 = "2E37A3D2DC2ECB0BD026C93055A71CAB4E568B062B1C9F7B8846E04DF1E9F3E6" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string29 = "94dc145b517036213443d4057d400296d40ffdcd50ba63f5304796060790c8a3" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string30 = "A0B3C96CA89770ED04E37D43188427E0016B42B03C0102216C5F6A785B942BD3" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string31 = "A1ECD50DA8AAE5734A5F5C4A6A951B5F3C99CC4FB939AC60EF5EE19896CA23A0" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string32 = "C2ACD3667483E5AC1E423E482DBA462E96DA3978776BFED07D9B436FEE135AB2" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string33 = "DBAB7B9CC694FC37354E3A18F9418586172ED6660D8D205EAFFF945525A6A31A" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string34 = "DCCDA4991BEBC5F2399C47C798981E7828ECC2BA77ED52A1D37BD866AD5582AA" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string35 = "F80AEB33FC53F2C8D6313A6B20CD117739A71382C208702B43073D54C9ACA681" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string36 = /FullyQualifiedAssemblyName\=0\;\\\\r\\\\nClrInstanceID\=StandIn/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string37 = "FuzzySecurity/StandIn" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string38 = "MlCGkaacS5SRUOt" nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string39 = /StandIn\.exe\s\-\-/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string40 = /StandIn\.exe\\"\s\-\-/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string41 = /StandIn_v12_Net35_45\.zip/ nocase ascii wide
        // Description: StandIn is a small .NET35/45 AD post-exploitation toolkit
        // Reference: https://github.com/FuzzySecurity/StandIn
        $string42 = /StandIn_v13_Net35_45\.zip/ nocase ascii wide
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

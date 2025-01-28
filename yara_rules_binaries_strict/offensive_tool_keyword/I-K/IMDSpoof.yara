rule IMDSpoof
{
    meta:
        description = "Detection patterns for the tool 'IMDSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IMDSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string1 = /\/etc\/systemd\/system\/IMDS\.service/
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string2 = /\/IMDSpoof\.git/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string3 = "grahamhelton/IMDSpoof" nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string4 = "IMDS Service Spoofing Enabled" nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string5 = "IMDSPoof Honey Token" nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string6 = /IMDSpoof.{0,100}IMDS\.go/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string7 = "IMDSpoof-main" nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string8 = "IQoJb3Jpz2cXpQRkpVX3Uf" nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string9 = "systemctl disable IMDS" nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string10 = "systemctl enable IMDS" nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string11 = "systemctl start IMDS" nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string12 = "systemctl status IMDS" nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string13 = "systemctl stop IMDS" nocase ascii wide
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

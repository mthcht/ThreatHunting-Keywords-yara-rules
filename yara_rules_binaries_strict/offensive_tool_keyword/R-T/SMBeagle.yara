rule SMBeagle
{
    meta:
        description = "Detection patterns for the tool 'SMBeagle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBeagle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string1 = " --dont-enumerate-acls " nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string2 = /\s\-\-dont\-enumerate\-acls\s.{0,100}\s\-e\s/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string3 = /\s\-\-scan\-local\-shares\s.{0,100}\s\-e\s/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string4 = "/SharpShares/Enums" nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string5 = "/SMBeagle" nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string6 = /\\WindowsShareFinder\.cs/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string7 = /SMBeagle\.exe/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string8 = /SMBeagle\.sln/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string9 = /smbeagle_.{0,100}_linux_amd64\.zip/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string10 = /smbeagle_.{0,100}_linux_arm64\.zip/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string11 = /smbeagle_.{0,100}_win_x64\.zip/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string12 = "using SMBeagle" nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string13 = /WindowsShareFinder\.cs/ nocase ascii wide
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

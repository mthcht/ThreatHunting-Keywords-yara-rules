rule go_lsass
{
    meta:
        description = "Detection patterns for the tool 'go-lsass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "go-lsass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string1 = /\/go\-lsass\.exe/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string2 = /\/go\-lsass\.git/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string3 = "/go-lsass/releases" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string4 = /\/go\-lsass\-master\.zip/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string5 = /\\go\-lsass\.exe/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string6 = /\\go\-lsass\-master\.zip/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string7 = /\\go\-lsass\-master\\/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string8 = "16386980a156fc6e9219ba230c5fd2759e4b43dff9261487598e7d0ecfe78ae0" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string9 = "455a614b6dd52b17b4af639045bd0c3c3ddad152334607978ec9e915553246e9" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string10 = "a7e8aade00d2cd5aeb6ec40d5b64f6cac88f120efb4efb719567e758af5892c2" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string11 = "db5a054172dcde3aebfb86b08e3bf8992f9df3d22e2028fd5154c647e7361ceb" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string12 = "go-lsass --host " nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string13 = "jfjallid/go-lsass" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string14 = "Successfully downloaded the LSASS dump into local file" nocase ascii wide
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

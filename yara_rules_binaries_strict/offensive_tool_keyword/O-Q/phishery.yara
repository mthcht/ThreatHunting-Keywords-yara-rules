rule phishery
{
    meta:
        description = "Detection patterns for the tool 'phishery' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "phishery"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string1 = /\/phishery\.exe/ nocase ascii wide
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string2 = /\/phishery\.git/ nocase ascii wide
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string3 = /\/phishery\/releases\/download\// nocase ascii wide
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string4 = /\\phishery\.exe/ nocase ascii wide
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string5 = /16bb30509efac0ba13c42eade477ab4454c5951c1c20f7c991c62798284aa3b0/ nocase ascii wide
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string6 = /334a8657b76c88f5d7b6a2be78cc4e9e6c5ecaeea5a104cea5e6d0c4250674a7/ nocase ascii wide
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string7 = /64591a6674fa71f5bf6858e009d487a56dc13d306cdab14a76e7b6fe49d4338b/ nocase ascii wide
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string8 = /8fa8dcae188d04bb3bb48782d5f97019c3a122816d9f48a6a8554ce211acb1f8/ nocase ascii wide
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string9 = /c2935d032a38a5a6d3251d22b9d93d08223b8dbf90efedbb0e6716cdafe76367/ nocase ascii wide
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string10 = /fd36746c68cdf7b32e63adaaa7b3e863b9769582f703722b88d9bf0b94030434/ nocase ascii wide
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string11 = /Injected\sWord\sdocument\shas\sbeen\ssaved\!/ nocase ascii wide
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string12 = /ryhanson\/phishery/ nocase ascii wide
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

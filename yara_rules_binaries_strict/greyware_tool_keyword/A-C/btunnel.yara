rule btunnel
{
    meta:
        description = "Detection patterns for the tool 'btunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "btunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string1 = /\/\.btunnel\./ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string2 = /\/btunnel\.exe/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string3 = /\/btunnel\.log/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string4 = /\\\.btunnel\./ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string5 = /\\bored\-tunnel\-client/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string6 = /\\btunnel\.exe/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string7 = /\\btunnel\.log/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string8 = "60e8a9e19b34ca6d9f1847504b7689b3f46b029ab07b4d13c6ccde026d78a0a4" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string9 = "af19236f06140b33ac3c78ae743627ba34dcd89be6d5c8dd22cac7f6eae19774" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string10 = /api\.btunnel\.in/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string11 = /bored\-tunnel\-client_Windows_x86_64\./ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string12 = "btunnel domain " nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string13 = "btunnel file " nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string14 = "btunnel http" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string15 = "btunnel tcp --" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string16 = "btunnel tcp" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string17 = /btunnel\.exe\shttp/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string18 = "eb1395952e6eb92d4f9a2babb56d29ef384d683387c6a990e79d5fe4ba86040f" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string19 = /http\:\/\/tcp\.btunnel\.in/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string20 = /https\:\/\/.{0,100}\.btunnel\.co\.in/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string21 = /https\:\/\/.{0,100}\.btunnel\.co\.in/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string22 = /https\:\/\/www\.btunnel\.in\/downloads/ nocase ascii wide
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

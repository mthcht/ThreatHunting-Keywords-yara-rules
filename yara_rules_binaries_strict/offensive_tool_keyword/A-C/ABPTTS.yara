rule ABPTTS
{
    meta:
        description = "Detection patterns for the tool 'ABPTTS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ABPTTS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string1 = /\/ABPTTS\.git/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string2 = /\\ABPTTS\-master/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string3 = /\=\=\=\[\[\[\sA\sBlack\sPath\sToward\sThe\sSun\s\]\]\]\=\=\=/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string4 = "63688c4f211155c76f2948ba21ebaf83" nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string5 = /abpttsclient\.py/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string6 = /ABPTTSClient\-log\.txt/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string7 = /abpttsfactory\.py/ nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string8 = "Building ABPTTS configuration " nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string9 = "nccgroup/ABPTTS" nocase ascii wide
        // Description: TCP tunneling over HTTP/HTTPS for web application servers
        // Reference: https://github.com/nccgroup/ABPTTS
        $string10 = "tQgGur6TFdW9YMbiyuaj9g6yBJb2tCbcgrEq" nocase ascii wide
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

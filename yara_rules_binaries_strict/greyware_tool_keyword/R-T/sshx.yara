rule sshx
{
    meta:
        description = "Detection patterns for the tool 'sshx' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshx"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string1 = /\s\-\-bin\ssshx\-server/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string2 = /\ss3\:\/\/sshx\// nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string3 = /\.vm\.sshx\.internal\:8051/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string4 = /\/release\/sshx\-server/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string5 = /\/sshx\-server\// nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string6 = /\\sshx\-.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string7 = /cargo\sinstall\ssshx/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string8 = /ekzhang\/sshx/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string9 = /https\:\/\/s3\.amazonaws\.com\/sshx\/sshx\-/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string10 = /https\:\/\/sshx\.io\/get/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string11 = /https\:\/\/sshx\.io\/s\// nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string12 = /sshx\-server\s\-\-listen/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string13 = /sshx\-server\-.{0,100}\.tar\.gz/ nocase ascii wide
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

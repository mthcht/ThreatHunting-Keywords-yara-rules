rule sshuttle
{
    meta:
        description = "Detection patterns for the tool 'sshuttle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshuttle"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string1 = " install sshuttle" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string2 = " py39-sshuttle" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string3 = " sshuttle:sshuttle " nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string4 = "/etc/sshuttle" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string5 = "/home/sshuttle" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string6 = /\/sshuttle\.git/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string7 = /\/sshuttle\.py/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string8 = "/sshuttle/tarball" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string9 = "/sshuttle/zipball" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string10 = "/tmp/sshuttle" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string11 = "b86e9468c1470e3a3e776f5cab91a1cb79927743cfbc92535e753024611e8b4e" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string12 = "net-proxy/sshuttle" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string13 = "sshuttle -" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string14 = /sshuttle\.cmdline/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string15 = /sshuttle\.firewall/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string16 = /sshuttle\.linux/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string17 = /sshuttle\.methods\.socket/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string18 = /sshuttle\.server/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string19 = /sshuttle\.service/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string20 = /sshuttle\.ssh/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string21 = "sshuttle/sshuttle" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string22 = "SSHUTTLE0001" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string23 = /sudoers\.d\/sshuttle_auto/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string24 = "systemctl start sshuttle" nocase ascii wide
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

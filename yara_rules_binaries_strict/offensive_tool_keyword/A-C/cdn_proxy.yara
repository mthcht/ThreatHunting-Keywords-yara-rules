rule cdn_proxy
{
    meta:
        description = "Detection patterns for the tool 'cdn-proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cdn-proxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string1 = "cdn_proxy cloudflare " nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string2 = /cdn_proxy_burp_ext\.py/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string3 = "cdn-proxy -" nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string4 = "cdn-proxy cloudfront " nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string5 = /cdn\-proxy\.git/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string6 = "cdn-proxy/burp_extension" nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string7 = "Cdn-Proxy-Host" nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string8 = "Cdn-Proxy-Origin" nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string9 = "cdn-scanner -" nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string10 = "install cdn-proxy" nocase ascii wide
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

rule trycloudflare_com
{
    meta:
        description = "Detection patterns for the tool 'trycloudflare.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "trycloudflare.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: The subdomain .trycloudflare.com is a temporary hostname provided by Cloudflare Tunnel - It allows users to expose local services to the internet without needing to configure port forwarding or a public IP - attackers frequently abuse it for malicious activities
        // Reference: https://www.forcepoint.com/blog/x-labs/asyncrat-python-trycloudflare-malware
        $string1 = /\.trycloudfare\.com.{0,100}DavWWWRoot/ nocase ascii wide
        // Description: The subdomain .trycloudflare.com is a temporary hostname provided by Cloudflare Tunnel - It allows users to expose local services to the internet without needing to configure port forwarding or a public IP - attackers frequently abuse it for malicious activities
        // Reference: https://www.forcepoint.com/blog/x-labs/asyncrat-python-trycloudflare-malware
        $string2 = /http\:\/\/.{0,100}\.trycloudfare\.com/ nocase ascii wide
        // Description: The subdomain .trycloudflare.com is a temporary hostname provided by Cloudflare Tunnel - It allows users to expose local services to the internet without needing to configure port forwarding or a public IP - attackers frequently abuse it for malicious activities
        // Reference: https://www.forcepoint.com/blog/x-labs/asyncrat-python-trycloudflare-malware
        $string3 = /https\:\/\/.{0,100}\.trycloudfare\.com/ nocase ascii wide
        // Description: Attackers abuse this service to expose malicious servers on a *.trycloudflare.com subdomain
        // Reference: https://lots-project.com/site/2a2e747279636c6f7564666c6172652e636f6d
        $string4 = /https\:\/\/.{0,100}\.trycloudflare\.com/ nocase ascii wide
        // Description: The subdomain .trycloudflare.com is a temporary hostname provided by Cloudflare Tunnel - It allows users to expose local services to the internet without needing to configure port forwarding or a public IP - attackers frequently abuse it for malicious activities
        // Reference: https://www.forcepoint.com/blog/x-labs/asyncrat-python-trycloudflare-malware
        $string5 = /location\:\\\\.{0,100}\.trycloudfare\.com/ nocase ascii wide
        // Description: The subdomain .trycloudflare.com is a temporary hostname provided by Cloudflare Tunnel - It allows users to expose local services to the internet without needing to configure port forwarding or a public IP - attackers frequently abuse it for malicious activities
        // Reference: https://www.forcepoint.com/blog/x-labs/asyncrat-python-trycloudflare-malware
        $string6 = /QNAME.{0,100}\.trycloudfare\.com/ nocase ascii wide
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

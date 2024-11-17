rule duckdns_org
{
    meta:
        description = "Detection patterns for the tool 'duckdns.org' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "duckdns.org"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string1 = /\/DuckDNS\.7z/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string2 = /\/DuckDNS\.git/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string3 = /\/DuckDNS\.zip\\"/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string4 = /\/duckdns\/duck\.log/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string5 = /\/duckdns\/duck\.sh/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string6 = /\/duckdns\-powershell\.git/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string7 = /\/opt\/duckdns\// nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string8 = /\\DuckDNS\.cfg/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string9 = /\\DuckDNS\.csproj/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string10 = /\\DuckDNS\.exe/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string11 = /\\DuckDNS\.lnk/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string12 = /\\DuckDNS\.sln/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string13 = /\\Update\-DuckDNS\.ps1/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string14 = /4B9C98F6\-AF30\-4280\-873D\-B45C7A7B89EB/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string15 = /8a35136501dde420ec5f3e88a7906c8c3d63af06621b47513befe8f09db3ed04/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string16 = /ataylor32\/duckdns\-powershell/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string17 = /chmod\s700\sduck\.sh/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string18 = /https\:\/\/www\.duckdns\.org\/update\?domains\=/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string19 = /jzelinskie\/duckdns/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string20 = /Sending\supdate\srequest\sto\sDuck\sDNS/ nocase ascii wide
        // Description: A simple C# DuckDNS updater - free dynamic DNS hosted on AWS - often used by threat actors for contacting C2
        // Reference: https://www.duckdns.org/install.jsp
        $string21 = /XWolfOverride\/DuckDNS/ nocase ascii wide
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

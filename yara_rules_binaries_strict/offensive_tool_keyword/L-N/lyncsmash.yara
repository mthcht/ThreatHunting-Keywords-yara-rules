rule lyncsmash
{
    meta:
        description = "Detection patterns for the tool 'lyncsmash' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lyncsmash"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string1 = /\.py\sdiscover\s\-H\sdomain_list\.txt/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string2 = /\.py\senum\s\-H\s.{0,100}\s\-U\s.{0,100}\.txt\s\-P\s.{0,100}\.txt\s\-.{0,100}\.txt/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string3 = /\.py\slock\s\-H\s.{0,100}\s\-u\sadministrator\s\-d\s/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string4 = /\/find_domain\.sh/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string5 = /\/lyncsmash\// nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string6 = /\/wordlists\/owa_directories\.txt/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string7 = /\/wordlists\/skype\-directories\.txt/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string8 = /1_FindDomain\.sh/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string9 = /2_lyncbrute\.sh/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string10 = /alexa\-top\-20000\-sites\.txt/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string11 = /brute_force_ntlm\.sh/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string12 = /find_domain\.sh\s/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string13 = /lyncsmash/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string14 = /lyncsmash\.git/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string15 = /lyncsmash\.log/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string16 = /lyncsmash\.py/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string17 = /lyncsmash\-master/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string18 = /ntlm\-info\.py/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string19 = /nyxgeek\/lyncsmash/ nocase ascii wide
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

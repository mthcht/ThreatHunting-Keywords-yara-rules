rule weakpass
{
    meta:
        description = "Detection patterns for the tool 'weakpass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "weakpass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string1 = /\/1\/all_in_one\.7z\.torrent/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string2 = /\/1\/all_in_one_p\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string3 = /\/1\/all_in_one_w\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string4 = /\/dicassassin\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string5 = /\/hashesorg2019\.gz/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string6 = /\/weakpass\.git/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string7 = /\/weakpass_2a\.gz/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string8 = /\/weakpass_3a\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string9 = /\\online_brute\.gz/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string10 = /cyclone\.hashesorg\.hashkiller\.combined/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string11 = /download\.weakpass\.com\// nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string12 = /github\.io\/weakpass\/generator\// nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string13 = /https\:\/\/weakpass\.com\// nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string14 = /js\-cracker\-client\/cracker\.js/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string15 = /online_brute\.gz\.torrent/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string16 = /weakpass\.com\/crack\-js/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string17 = /weakpass\.com\/generate/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string18 = /weakpass\.com\/wordlist\// nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string19 = /weakpass\/crack\-js/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string20 = /weakpass_3\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string21 = /weakpass_3a\.7z\.torrent/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string22 = /weakpass\-main\./ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string23 = /wordlists.{0,100}all_in_one\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string24 = /xsukax\-Wordlist\-All\.7z/ nocase ascii wide
        // Description: Weakpass collection of tools for bruteforce and hashcracking
        // Reference: https://github.com/zzzteph/weakpass
        $string25 = /zzzteph\/weakpass/ nocase ascii wide
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

rule wordlists
{
    meta:
        description = "Detection patterns for the tool 'wordlists' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wordlists"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string1 = /\sinstall\swordlists/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string2 = /\s\-u\swordlist\s.{0,100}\swordlist_uniq_sorted/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string3 = /\/amass\/wordlists/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string4 = /\/brutespray\// nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string5 = /\/dirbuster\// nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string6 = /\/fb_firstlast\.7z/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string7 = /\/fern\-wifi\-cracker\// nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string8 = /\/rockyou\.txt/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string9 = /\/top_mots_combo\.7z/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string10 = /\/Web\/decouverte\.txt/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string11 = /\/Web\/discovery\.txt/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string12 = /\/wikipedia_fr\.7z/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string13 = /clem9669_wordlist_medium\.7z/ nocase ascii wide
        // Description: Various wordlists FR & EN - Cracking French passwords
        // Reference: https://github.com/clem9669/wordlists
        $string14 = /clem9669_wordlist_small\.7z/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string15 = /dirb\/wordlists/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string16 = /fasttrack\/wordlist\.txt/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string17 = /john\/password\.lst/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string18 = /nselib\/data\/passwords\.lst/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string19 = /rockyou\.txt\.gz/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string20 = /sqlmap\/data\/txt\/wordlist\.txt/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string21 = /usr\/share\/seclists/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string22 = /wfuzz\/wordlist/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string23 = /wordlist_TLAs\.txt/ nocase ascii wide
        // Description: package contains the rockyou.txt wordlist
        // Reference: https://www.kali.org/tools/wordlists/
        $string24 = /wordlist\-probable\.txt/ nocase ascii wide
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

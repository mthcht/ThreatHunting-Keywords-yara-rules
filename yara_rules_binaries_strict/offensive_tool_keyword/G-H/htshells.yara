rule htshells
{
    meta:
        description = "Detection patterns for the tool 'htshells' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "htshells"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string1 = /\sprepare\.sh\sshell\/mod_.{0,100}\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string2 = /\/htshells\.git/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string3 = /\/prepare\.sh\sshell\/mod_.{0,100}\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string4 = /htshells\-master/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string5 = /http\:\/\/.{0,100}\/\.htaccess\?c\=cmd/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string6 = /http\:\/\/.{0,100}\/\.htaccess\?c\=uname\s\-a/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string7 = /https\:\/\/.{0,100}\/\.htaccess\?c\=cmd/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string8 = /https\:\/\/.{0,100}\/\.htaccess\?c\=uname\s\-a/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string9 = /mod_auth_remote\.phish\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string10 = /mod_caucho\.shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string11 = /mod_cgi\.shell\.bash\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string12 = /mod_cgi\.shell\.bind\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string13 = /mod_cgi\.shell\.windows\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string14 = /mod_mono\.shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string15 = /mod_multi\.shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string16 = /mod_perl\.embperl\.shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string17 = /mod_perl\.IPP\.shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string18 = /mod_perl\.Mason\.shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string19 = /mod_perl\.shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string20 = /mod_php\.shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string21 = /mod_php\.shell2\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string22 = /mod_php\.stealth\-shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string23 = /mod_python\.shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string24 = /mod_rivet\.shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string25 = /mod_ruby\.shell\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string26 = /mod_sendmail\.rce\.htaccess/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string27 = /wireghoul\/htshells/ nocase ascii wide
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

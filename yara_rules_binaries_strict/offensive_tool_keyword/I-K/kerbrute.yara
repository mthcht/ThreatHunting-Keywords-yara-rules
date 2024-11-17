rule kerbrute
{
    meta:
        description = "Detection patterns for the tool 'kerbrute' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kerbrute"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string1 = /\sbruteuser\s/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string2 = /\sbruteuser\s\-d\s/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string3 = /\skerbrute\.py/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string4 = /\spasswordspray\s\-d\s/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string5 = /\s\-\-user\-as\-pass/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string6 = /\suserenum\s\-d\s.{0,100}\s.{0,100}\.txt/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string7 = /\.\/kerbrute\s/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string8 = /\/kerbrute\.git/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string9 = /\/kerbrute\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string10 = /\/kerbrute\.py/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string11 = /\/kerbrute\// nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string12 = /\/userenum\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string13 = /\/userenum\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string14 = /\\kerbrute\.py/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string15 = /ASRepToHashcat/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string16 = /bruteforce\s.{0,100}\.txt/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string17 = /bruteforce\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string18 = /bruteForceCombos/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string19 = /bruteForceUser/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string20 = /bruteuser\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string21 = /bruteuserCmd/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string22 = /cmd\/bruteforce\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string23 = /cmd\/bruteuser\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string24 = /\-d\s.{0,100}\sbruteforce\s\-/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string25 = /Got\sencrypted\sTGT\sfor\s.{0,100}\sbut\scouldn\'t\sconvert\sto\shash/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string26 = /has\sno\spre\sauth\srequired\.\sDumping\shash\sto\scrack\soffline\:/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string27 = /install\skerbrute/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string28 = /kerbrute\s\-/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string29 = /kerbrute\suserenum\s/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string30 = /kerbrute.{0,100}bruteforce/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string31 = /kerbrute\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string32 = /kerbrute\/cmd/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string33 = /kerbrute\/util/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string34 = /kerbrute_.{0,100}\.exe/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string35 = /kerbrute_darwin_386/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string36 = /kerbrute_darwin_amd64/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string37 = /kerbrute_linux/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string38 = /kerbrute_windows/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string39 = /kerbrute_windows_386\.exe/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string40 = /kerbrute_windows_amd64\.exe/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string41 = /kerbrute\-master/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string42 = /KerbruteSession/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string43 = /passwordspray.{0,100}\-\-user\-as\-pass/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string44 = /passwordspray\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string45 = /passwordSprayCmd/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string46 = /ropnop\/kerbrute/ nocase ascii wide
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

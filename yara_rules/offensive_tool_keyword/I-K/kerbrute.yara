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
        $string6 = /\suserenum\s\-d\s.{0,1000}\s.{0,1000}\.txt/ nocase ascii wide
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
        $string16 = /bruteforce\s.{0,1000}\.txt/ nocase ascii wide
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
        $string24 = /\-d\s.{0,1000}\sbruteforce\s\-/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string25 = /Got\sencrypted\sTGT\sfor\s.{0,1000}\sbut\scouldn\'t\sconvert\sto\shash/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string26 = /has\sno\spre\sauth\srequired\.\sDumping\shash\sto\scrack\soffline\:/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string27 = /kerbrute\s\-/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string28 = /kerbrute\suserenum\s/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string29 = /kerbrute.{0,1000}bruteforce/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string30 = /kerbrute\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string31 = /kerbrute\/cmd/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string32 = /kerbrute\/util/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string33 = /kerbrute_.{0,1000}\.exe/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string34 = /kerbrute_darwin_386/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string35 = /kerbrute_darwin_amd64/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string36 = /kerbrute_linux/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string37 = /kerbrute_windows/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string38 = /kerbrute_windows_386\.exe/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string39 = /kerbrute_windows_amd64\.exe/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string40 = /kerbrute\-master/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string41 = /KerbruteSession/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string42 = /passwordspray.{0,1000}\-\-user\-as\-pass/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string43 = /passwordspray\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string44 = /passwordSprayCmd/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string45 = /ropnop\/kerbrute/ nocase ascii wide

    condition:
        any of them
}

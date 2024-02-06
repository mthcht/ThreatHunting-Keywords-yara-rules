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
        $string5 = /\spasswordspray\s\-d\s/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string6 = /\s\-\-user\-as\-pass/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string7 = /\suserenum\s\-d\s.{0,1000}\s.{0,1000}\.txt/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string8 = /\.\/kerbrute\s/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string9 = /\/kerbrute\.git/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string10 = /\/kerbrute\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string11 = /\/kerbrute\.py/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string12 = /\/kerbrute\// nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string13 = /\/userenum\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string14 = /\/userenum\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string15 = /\\kerbrute\.py/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string16 = /ASRepToHashcat/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string17 = /bruteforce\s.{0,1000}\.txt/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string18 = /bruteforce\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string19 = /bruteForceCombos/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string20 = /bruteForceUser/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string21 = /bruteForceUser/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string22 = /bruteuser\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string23 = /bruteuserCmd/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string24 = /cmd\/bruteforce\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string25 = /cmd\/bruteuser\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string26 = /\-d\s.{0,1000}\sbruteforce\s\-/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string27 = /Got\sencrypted\sTGT\sfor\s.{0,1000}\sbut\scouldn\'t\sconvert\sto\shash/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string28 = /has\sno\spre\sauth\srequired\.\sDumping\shash\sto\scrack\soffline\:/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string29 = /kerbrute\s\-/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string30 = /kerbrute\s\-/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string31 = /kerbrute\suserenum\s/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string32 = /kerbrute.{0,1000}bruteforce/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string33 = /kerbrute\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string34 = /kerbrute\/cmd/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string35 = /kerbrute\/util/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string36 = /kerbrute_.{0,1000}\.exe/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string37 = /kerbrute_darwin_386/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string38 = /kerbrute_darwin_amd64/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string39 = /kerbrute_linux/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string40 = /kerbrute_linux/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string41 = /kerbrute_windows/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string42 = /kerbrute_windows_386\.exe/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string43 = /kerbrute_windows_amd64\.exe/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string44 = /kerbrute\-master/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string45 = /KerbruteSession/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string46 = /passwordspray.{0,1000}\-\-user\-as\-pass/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string47 = /passwordspray\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string48 = /passwordspray\.go/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string49 = /passwordSprayCmd/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string50 = /ropnop\/kerbrute/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string51 = /ropnop\/kerbrute/ nocase ascii wide

    condition:
        any of them
}

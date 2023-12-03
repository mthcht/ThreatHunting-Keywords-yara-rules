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
        $string1 = /.{0,1000}\sbruteuser\s.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string2 = /.{0,1000}\sbruteuser\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string3 = /.{0,1000}\skerbrute\.py.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string4 = /.{0,1000}\spasswordspray\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string5 = /.{0,1000}\spasswordspray\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string6 = /.{0,1000}\s\-\-user\-as\-pass.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string7 = /.{0,1000}\suserenum\s\-d\s.{0,1000}\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string8 = /.{0,1000}\.\/kerbrute\s.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string9 = /.{0,1000}\/kerbrute\.git.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string10 = /.{0,1000}\/kerbrute\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string11 = /.{0,1000}\/kerbrute\.py.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string12 = /.{0,1000}\/kerbrute\/.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string13 = /.{0,1000}\/userenum\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string14 = /.{0,1000}\/userenum\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string15 = /.{0,1000}\\kerbrute\.py.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string16 = /.{0,1000}ASRepToHashcat.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string17 = /.{0,1000}bruteforce\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string18 = /.{0,1000}bruteforce\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string19 = /.{0,1000}bruteForceCombos.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string20 = /.{0,1000}bruteForceUser.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string21 = /.{0,1000}bruteForceUser.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string22 = /.{0,1000}bruteuser\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string23 = /.{0,1000}bruteuserCmd.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string24 = /.{0,1000}cmd\/bruteforce\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string25 = /.{0,1000}cmd\/bruteuser\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string26 = /.{0,1000}\-d\s.{0,1000}\sbruteforce\s\-.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string27 = /.{0,1000}Got\sencrypted\sTGT\sfor\s.{0,1000}\sbut\scouldn\'t\sconvert\sto\shash.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string28 = /.{0,1000}has\sno\spre\sauth\srequired\.\sDumping\shash\sto\scrack\soffline:.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string29 = /.{0,1000}kerbrute\s\-.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string30 = /.{0,1000}kerbrute\s\-.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string31 = /.{0,1000}kerbrute\suserenum\s.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string32 = /.{0,1000}kerbrute.{0,1000}bruteforce.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string33 = /.{0,1000}kerbrute\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string34 = /.{0,1000}kerbrute\/cmd.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string35 = /.{0,1000}kerbrute\/util.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string36 = /.{0,1000}kerbrute_.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string37 = /.{0,1000}kerbrute_darwin_386.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string38 = /.{0,1000}kerbrute_darwin_amd64.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string39 = /.{0,1000}kerbrute_linux.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string40 = /.{0,1000}kerbrute_linux.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string41 = /.{0,1000}kerbrute_windows.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string42 = /.{0,1000}kerbrute_windows_386\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string43 = /.{0,1000}kerbrute_windows_amd64\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string44 = /.{0,1000}kerbrute\-master.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string45 = /.{0,1000}KerbruteSession.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string46 = /.{0,1000}passwordspray.{0,1000}\-\-user\-as\-pass.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string47 = /.{0,1000}passwordspray\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string48 = /.{0,1000}passwordspray\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string49 = /.{0,1000}passwordSprayCmd.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string50 = /.{0,1000}ropnop\/kerbrute.{0,1000}/ nocase ascii wide
        // Description: A tool to perform Kerberos pre-auth bruteforcing
        // Reference: https://github.com/ropnop/kerbrute
        $string51 = /.{0,1000}ropnop\/kerbrute.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

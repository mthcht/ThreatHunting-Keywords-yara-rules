rule SOAPHound
{
    meta:
        description = "Detection patterns for the tool 'SOAPHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SOAPHound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string1 = " --bhdump " nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string2 = " --certdump " nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string3 = " --dnsdump " nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string4 = /\sSOAPHound\.ADWS/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string5 = /\\"ADWS\srequest\swith\sldapbase\s\(/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string6 = "\"Dump BH data\"" nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string7 = /\(\!soaphound\=/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string8 = /\.exe\s\s\-\-buildcache\s\-c\s.{0,1000}\\cache\.txt/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string9 = /\.exe\s\-\-showstats\s\-c\s.{0,1000}\\cache\.txt/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string10 = /\/SOAPHound\.exe/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string11 = /\/SOAPHound\.git/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string12 = /\/SOAPHound\/Program\.cs/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string13 = /\\SOAPHound\.csproj/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string14 = /\\SOAPHound\.exe/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string15 = /\\SOAPHound\.sln/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string16 = /\\SOAPHound\\Enums\\/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string17 = /\\SOAPHound\\Program\.cs/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string18 = /\\SOAPHound\-master/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string19 = "33571B09-4E94-43CB-ABDC-0226D769E701" nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string20 = /Domain\scontroller\sis\smissing.{0,1000}\suse\s\-\-dc\./ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string21 = "Dump AD Certificate Services data" nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string22 = "Dump AD Integrated DNS data" nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string23 = "FalconForceTeam/SOAPHound" nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string24 = "Password to use for ADWS Connection" nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string25 = /SOAPHound\sPoC\s1\.0\.1\-beta/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string26 = /SOAPHound\.exe\s/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string27 = /SOAPHound\.Processors/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string28 = "Specify domain for enumeration" nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string29 = /Username\sto\suse\sfor\sADWS\sConnection\.\sFormat\:\sdomain\\\\user\sor\suser\@domain/ nocase ascii wide

    condition:
        any of them
}

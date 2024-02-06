rule chaos
{
    meta:
        description = "Detection patterns for the tool 'chaos' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chaos"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string1 = /\schaos\.exe\s/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string2 = /\sSQLITE_DATABASE\=chaos/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string3 = /\/CHAOS\.git/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string4 = /\/CHAOS\-5\.0\.1\.zip/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string5 = /\/chaos\-container\:\/database\// nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string6 = /\\chaos\.exe/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string7 = /\\CHAOS\-5\.0\.1\.zip/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string8 = /\\CHAOS\-master\.zip/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string9 = /c\:\/chaos\-container\:\/database\// nocase ascii wide
        // Description: Chaos ransomware behavior
        // Reference: https://blog.qualys.com/vulnerabilities-threat-research/2022/01/17/the-chaos-ransomware-can-be-ravaging
        $string10 = /C\:\\Users\\.{0,1000}\\AppData\\Roaming\\svchost\.exe/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string11 = /chaos.{0,1000}persistence_enable/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string12 = /go\srun\scmd\/chaos\/main\.go/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string13 = /md\sc\:\\chaos\-container/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string14 = /tiagorlampert\/CHAOS/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string15 = /tiagorlampert\/chaos\:latest/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string16 = /tiagorlampert\@gmail\.com/ nocase ascii wide

    condition:
        any of them
}

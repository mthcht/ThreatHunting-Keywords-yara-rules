rule MDE_Enum
{
    meta:
        description = "Detection patterns for the tool 'MDE_Enum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MDE_Enum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string1 = /\/MDE_Enum\.git/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string2 = /\[\+\]\sEnumerating\sASR\sRules\son\sLocal\sSystem/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string3 = /\[\+\]\sEnumerating\sASR\sRules\son\sRemote\sSystem\s/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string4 = /\\MDE_Enum\.csproj/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string5 = /\\MDE_Enum\.exe/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string6 = /\\MDE_Enum\\Program\.cs/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string7 = /\>MDE_Enum\</ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string8 = /0xsp\-SRD\/MDE_Enum/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string9 = /5EC16C3F\-1E62\-4661\-8C20\-504CB0E55441/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string10 = /65cf6179c85728317f11460314779b365ba77199352a2b11624729f788daf6bc/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string11 = /7b39a858a51efa5160d65300b9b89695caf33ec380f69a40cdb7f742e8f05a46/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string12 = /MDE_Enum\s\/local\s\/asr/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string13 = /MDE_Enum\s\/local\s\/paths/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string14 = /ObjectQuery\(\"SELECT\s.{0,1000}\sFROM\sMSFT_MpPreference\"\)/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string15 = /Remote\sSystem\s\-\sMDE_Enum\s/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string16 = /\-Retrieve\sDefender\sASR\sTriggered\sEvents\s\-/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string17 = /\-Retrieve\sDefender\sExclusion\sPaths\sUsing\sEvent\sLogs\s\-/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string18 = /using\sMDE_Enum\;/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string19 = /WindowsDefenderEventLog_Enum\s/ nocase ascii wide

    condition:
        any of them
}

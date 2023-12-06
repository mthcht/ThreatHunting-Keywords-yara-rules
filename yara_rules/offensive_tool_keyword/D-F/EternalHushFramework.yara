rule EternalHushFramework
{
    meta:
        description = "Detection patterns for the tool 'EternalHushFramework' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EternalHushFramework"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string1 = /\sEternalHushCore\s/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string2 = /\/EternalHushCore\.dll/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string3 = /\/EternalHushFramework\.git/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string4 = /\\EternalHushCore\.dll/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string5 = /\\EternalHushCore\\/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string6 = /APT64\/EternalHushFramework/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string7 = /EternalHushFramework\-.{0,1000}\-SNAPSHOT\.jar/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string8 = /EternalHushFramework\-main/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string9 = /EternalHushMain\.java/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string10 = /EternalHushWindow\.java/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string11 = /import\s_eternalhush/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string12 = /import\seternalhush\./ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string13 = /SELECT\s.{0,1000}\sFROM\sEvilSignature/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string14 = /W2F1dG9ydW5dDQpzaGVsbGV4ZWN1dGU9eTMyNHNlZHguZXhlDQppY29uPSVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxTSEVMTDMyLmRsbCw0DQphY3Rpb249T3BlbiBmb2xkZXIgdG8gdmlldyBmaWxlcw0Kc2hlbGxcZGVmYXVsdD1PcGVuDQpzaGVsbFxkZWZhdWx0XGNvbW1hbmQ9eTMyNHNlZHguZXhlDQpzaGVsbD1kZWZhdWx0/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string15 = /X32_ClSp_Tcp_Exe\.exe/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string16 = /X64_ClSp_Tcp_Exe\.exe/ nocase ascii wide

    condition:
        any of them
}

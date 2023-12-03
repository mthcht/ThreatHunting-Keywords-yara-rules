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
        $string1 = /.{0,1000}\sEternalHushCore\s.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string2 = /.{0,1000}\/EternalHushCore\.dll.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string3 = /.{0,1000}\/EternalHushFramework\.git.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string4 = /.{0,1000}\\EternalHushCore\.dll.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string5 = /.{0,1000}\\EternalHushCore\\.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string6 = /.{0,1000}APT64\/EternalHushFramework.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string7 = /.{0,1000}EternalHushFramework\-.{0,1000}\-SNAPSHOT\.jar.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string8 = /.{0,1000}EternalHushFramework\-main.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string9 = /.{0,1000}EternalHushMain\.java.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string10 = /.{0,1000}EternalHushWindow\.java.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string11 = /.{0,1000}import\s_eternalhush.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string12 = /.{0,1000}import\seternalhush\..{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string13 = /.{0,1000}SELECT\s.{0,1000}\sFROM\sEvilSignature.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string14 = /.{0,1000}W2F1dG9ydW5dDQpzaGVsbGV4ZWN1dGU9eTMyNHNlZHguZXhlDQppY29uPSVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxTSEVMTDMyLmRsbCw0DQphY3Rpb249T3BlbiBmb2xkZXIgdG8gdmlldyBmaWxlcw0Kc2hlbGxcZGVmYXVsdD1PcGVuDQpzaGVsbFxkZWZhdWx0XGNvbW1hbmQ9eTMyNHNlZHguZXhlDQpzaGVsbD1kZWZhdWx0.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string15 = /.{0,1000}X32_ClSp_Tcp_Exe\.exe.{0,1000}/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string16 = /.{0,1000}X64_ClSp_Tcp_Exe\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

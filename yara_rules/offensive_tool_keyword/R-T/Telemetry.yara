rule Telemetry
{
    meta:
        description = "Detection patterns for the tool 'Telemetry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Telemetry"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string1 = " Remotely download Trojan files to " nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string2 = /\/Telemetry\.git/ nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string3 = /\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\fun/ nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string4 = "2f00a05b-263d-4fcc-846b-da82bd684603" nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string5 = "58de3ab6935d1248e937e333e917586efb058e8b7d65ade38989543c806bd23e" nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string6 = "5f026c27-f8e6-4052-b231-8451c6a73838" nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string7 = "5F026C27-F8E6-4052-B231-8451C6A73838" nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string8 = "6455d210924926d364ebf88ff053821ff2d603ea99b17d1dbb454a7d061992cc" nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string9 = "d7a308da069dcf3990f4cbfe57b8a1cc79c5f6b1259da795bba61592b8cf4b08" nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string10 = "Execute command without file backdoor" nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string11 = /https\:\/\/www\.trustedsec\.com\/blog\/abusing\-windows\-telemetry\-for\-persistence\// nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string12 = "Imanfeng/Telemetry" nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string13 = /TELEMETRY\.exe\sinstall\s/ nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string14 = /TELEMETRY\.exe\sinstall\s\/command\:/ nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string15 = /TELEMETRY\.exe\sinstall\s\/path\:/ nocase ascii wide
        // Description: Abusing Windows Telemetry for persistence through registry modifications and scheduled tasks to execute arbitrary commands with system-level privileges.
        // Reference: https://github.com/Imanfeng/Telemetry
        $string16 = /TELEMETRY\.exe\sinstall\s\/url\:/ nocase ascii wide

    condition:
        any of them
}

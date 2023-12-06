rule EDRaser
{
    meta:
        description = "Detection patterns for the tool 'EDRaser' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRaser"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string1 = /\s\-attack\sremote_db\s\-db_type\s.{0,1000}\s\-db_username\s.{0,1000}\s\-db_password\s/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string2 = /\s\-attack\swindows_application_event_log_local/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string3 = /\s\-attack\swindows_event_log/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string4 = /\s\-attack\swindows_security_event_log_remote/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string5 = /\s\-attak\ssyslog/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string6 = /\sedraser\.py/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string7 = /\/EDRaser\.git/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string8 = /\/edraser\.py/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string9 = /\/evilSignatures\.db/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string10 = /\\edraser\.py/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string11 = /\\evilSignatures\.db/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string12 = /edraser\.py\s\-/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string13 = /EDRaser\-main/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string14 = /SafeBreach\-Labs\/EDRaser/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string15 = /SELECT\s.{0,1000}\sFROM\sEvilSignature/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string16 = /W2F1dG9ydW5dDQpzaGVsbGV4ZWN1dGU9eTMyNHNlZHguZXhlDQppY29uPSVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxTSEVMTDMyLmRsbCw0DQphY3Rpb249T3BlbiBmb2xkZXIgdG8gdmlldyBmaWxlcw0Kc2hlbGxcZGVmYXVsdD1PcGVuDQpzaGVsbFxkZWZhdWx0XGNvbW1hbmQ9eTMyNHNlZHguZXhlDQpzaGVsbD1kZWZhdWx0/ nocase ascii wide

    condition:
        any of them
}

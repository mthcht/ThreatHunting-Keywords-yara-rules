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
        $string1 = /.{0,1000}\s\-attack\sremote_db\s\-db_type\s.{0,1000}\s\-db_username\s.{0,1000}\s\-db_password\s.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string2 = /.{0,1000}\s\-attack\swindows_application_event_log_local.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string3 = /.{0,1000}\s\-attack\swindows_event_log.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string4 = /.{0,1000}\s\-attack\swindows_security_event_log_remote.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string5 = /.{0,1000}\s\-attak\ssyslog.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string6 = /.{0,1000}\sedraser\.py.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string7 = /.{0,1000}\/EDRaser\.git.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string8 = /.{0,1000}\/edraser\.py.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string9 = /.{0,1000}\/evilSignatures\.db.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string10 = /.{0,1000}\\edraser\.py.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string11 = /.{0,1000}\\evilSignatures\.db.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string12 = /.{0,1000}edraser\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string13 = /.{0,1000}EDRaser\-main.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string14 = /.{0,1000}SafeBreach\-Labs\/EDRaser.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string15 = /.{0,1000}SELECT\s.{0,1000}\sFROM\sEvilSignature.{0,1000}/ nocase ascii wide
        // Description: EDRaser is a powerful tool for remotely deleting access logs & Windows event logs & databases and other files on remote machines.
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string16 = /.{0,1000}W2F1dG9ydW5dDQpzaGVsbGV4ZWN1dGU9eTMyNHNlZHguZXhlDQppY29uPSVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxTSEVMTDMyLmRsbCw0DQphY3Rpb249T3BlbiBmb2xkZXIgdG8gdmlldyBmaWxlcw0Kc2hlbGxcZGVmYXVsdD1PcGVuDQpzaGVsbFxkZWZhdWx0XGNvbW1hbmQ9eTMyNHNlZHguZXhlDQpzaGVsbD1kZWZhdWx0.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

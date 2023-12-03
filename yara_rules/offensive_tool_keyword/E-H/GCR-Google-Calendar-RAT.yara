rule GCR_Google_Calendar_RAT
{
    meta:
        description = "Detection patterns for the tool 'GCR-Google-Calendar-RAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GCR-Google-Calendar-RAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Google Calendar RAT is a PoC of Command&Control over Google Calendar Events
        // Reference: https://github.com/MrSaighnal/GCR-Google-Calendar-RAT
        $string1 = /.{0,1000}\.\/gcr\.py.{0,1000}/ nocase ascii wide
        // Description: Google Calendar RAT is a PoC of Command&Control over Google Calendar Events
        // Reference: https://github.com/MrSaighnal/GCR-Google-Calendar-RAT
        $string2 = /.{0,1000}GCR\s\-\sGoogle\sCalendar\sRAT.{0,1000}/ nocase ascii wide
        // Description: Google Calendar RAT is a PoC of Command&Control over Google Calendar Events
        // Reference: https://github.com/MrSaighnal/GCR-Google-Calendar-RAT
        $string3 = /.{0,1000}GCR\-Google\-Calendar\-RAT.{0,1000}/ nocase ascii wide
        // Description: Google Calendar RAT is a PoC of Command&Control over Google Calendar Events
        // Reference: https://github.com/MrSaighnal/GCR-Google-Calendar-RAT
        $string4 = /.{0,1000}main\/gcr\.py.{0,1000}/ nocase ascii wide
        // Description: Google Calendar RAT is a PoC of Command&Control over Google Calendar Events
        // Reference: https://github.com/MrSaighnal/GCR-Google-Calendar-RAT
        $string5 = /.{0,1000}python3\sgcr\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

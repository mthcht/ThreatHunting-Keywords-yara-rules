rule h8mail
{
    meta:
        description = "Detection patterns for the tool 'h8mail' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "h8mail"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Powerful and user-friendly password hunting tool.
        // Reference: https://github.com/opencubicles/h8mail
        $string1 = /.{0,1000}\/h8mail\/.{0,1000}/ nocase ascii wide
        // Description: Powerful and user-friendly password hunting tool.
        // Reference: https://github.com/opencubicles/h8mail
        $string2 = /.{0,1000}h8mail\s\-.{0,1000}/ nocase ascii wide
        // Description: h8mail is an email OSINT and breach hunting tool using different breach and reconnaissance services. or local breaches such as Troy Hunts Collection1 and the infamous Breach Compilation torrent
        // Reference: https://github.com/khast3x/h8mail
        $string3 = /.{0,1000}h8mail.{0,1000}/ nocase ascii wide
        // Description: Powerful and user-friendly password hunting tool.
        // Reference: https://github.com/opencubicles/h8mail
        $string4 = /.{0,1000}install\sh8mail.{0,1000}/ nocase ascii wide
        // Description: Powerful and user-friendly password hunting tool.
        // Reference: https://github.com/opencubicles/h8mail
        $string5 = /.{0,1000}khast3x\/h8mail.{0,1000}/ nocase ascii wide
        // Description: Powerful and user-friendly password hunting tool.
        // Reference: https://github.com/opencubicles/h8mail
        $string6 = /.{0,1000}opencubicles\/h8mail.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

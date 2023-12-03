rule teamsphisher
{
    meta:
        description = "Detection patterns for the tool 'teamsphisher' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teamsphisher"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string1 = /.{0,1000}\s\-\-greeting\s.{0,1000}\s\-\-personalize\s.{0,1000}\-\-securelink.{0,1000}/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string2 = /.{0,1000}\/Teamphisher\.txt.{0,1000}/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string3 = /.{0,1000}\/Teamphisher\/targets\.txt.{0,1000}/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string4 = /.{0,1000}best.{0,1000}phish\sher.{0,1000}/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string5 = /.{0,1000}myreallycooltotallyrealtenant\.onmicrosoft\.com.{0,1000}/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string6 = /.{0,1000}Octoberfest7\/TeamsPhisher.{0,1000}/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string7 = /.{0,1000}TeamsPhisher\.git.{0,1000}/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string8 = /.{0,1000}teamsphisher\.log.{0,1000}/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string9 = /.{0,1000}teamsphisher\.py.{0,1000}/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string10 = /.{0,1000}TeamsPhisher\-main\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

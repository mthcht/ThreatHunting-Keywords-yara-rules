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
        $string1 = /\s\-\-greeting\s.{0,1000}\s\-\-personalize\s.{0,1000}\-\-securelink/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string2 = /\/Teamphisher\.txt/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string3 = /\/Teamphisher\/targets\.txt/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string4 = /best.{0,1000}phish\sher/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string5 = /myreallycooltotallyrealtenant\.onmicrosoft\.com/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string6 = /Octoberfest7\/TeamsPhisher/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string7 = /TeamsPhisher\.git/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string8 = /teamsphisher\.log/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string9 = /teamsphisher\.py/ nocase ascii wide
        // Description: Send phishing messages and attachments to Microsoft Teams users
        // Reference: https://github.com/Octoberfest7/TeamsPhisher
        $string10 = /TeamsPhisher\-main\.zip/ nocase ascii wide

    condition:
        any of them
}

rule jecretz
{
    meta:
        description = "Detection patterns for the tool 'jecretz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "jecretz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Jira Secret Hunter - Helps you find credentials and sensitive contents in Jira tickets
        // Reference: https://github.com/sahadnk72/jecretz
        $string1 = /\sjecretz\.py/ nocase ascii wide
        // Description: Jira Secret Hunter - Helps you find credentials and sensitive contents in Jira tickets
        // Reference: https://github.com/sahadnk72/jecretz
        $string2 = /\/jecretz\.git/ nocase ascii wide
        // Description: Jira Secret Hunter - Helps you find credentials and sensitive contents in Jira tickets
        // Reference: https://github.com/sahadnk72/jecretz
        $string3 = /\/jecretz\.py/ nocase ascii wide
        // Description: Jira Secret Hunter - Helps you find credentials and sensitive contents in Jira tickets
        // Reference: https://github.com/sahadnk72/jecretz
        $string4 = /\[\+\]\sJecretz\sResults/ nocase ascii wide
        // Description: Jira Secret Hunter - Helps you find credentials and sensitive contents in Jira tickets
        // Reference: https://github.com/sahadnk72/jecretz
        $string5 = /\\jecretz\.py/ nocase ascii wide
        // Description: Jira Secret Hunter - Helps you find credentials and sensitive contents in Jira tickets
        // Reference: https://github.com/sahadnk72/jecretz
        $string6 = "c18c8abdaeacc30c7bdc46cf7565e5255aae8df8f34b7964ff09d35736d2816c" nocase ascii wide
        // Description: Jira Secret Hunter - Helps you find credentials and sensitive contents in Jira tickets
        // Reference: https://github.com/sahadnk72/jecretz
        $string7 = "Jecretz, Jira Secrets Hunter" nocase ascii wide
        // Description: Jira Secret Hunter - Helps you find credentials and sensitive contents in Jira tickets
        // Reference: https://github.com/sahadnk72/jecretz
        $string8 = /jira.{0,1000}\/rest\/issueNav\/1\/issueTable/ nocase ascii wide
        // Description: Jira Secret Hunter - Helps you find credentials and sensitive contents in Jira tickets
        // Reference: https://github.com/sahadnk72/jecretz
        $string9 = "sahadnk72/jecretz" nocase ascii wide

    condition:
        any of them
}

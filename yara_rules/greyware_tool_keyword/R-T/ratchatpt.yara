rule ratchatpt
{
    meta:
        description = "Detection patterns for the tool 'ratchatpt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ratchatpt"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string1 = /https\:\/\/api\.openai\.com\/v1\/files/ nocase ascii wide

    condition:
        any of them
}

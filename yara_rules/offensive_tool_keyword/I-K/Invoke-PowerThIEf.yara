rule Invoke_PowerThIEf
{
    meta:
        description = "Detection patterns for the tool 'Invoke-PowerThIEf' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-PowerThIEf"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An IE Post Exploitation Library released at Steelcon in Sheffield 7th July 2018.
        // Reference: https://github.com/nettitude/Invoke-PowerThIEf
        $string1 = /Invoke\-PowerThIEf/ nocase ascii wide

    condition:
        any of them
}

rule EyeWitness
{
    meta:
        description = "Detection patterns for the tool 'EyeWitness' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EyeWitness"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EyeWitness is designed to take screenshots of websites provide some server header info. and identify default credentials if known.EyeWitness is designed to run on Kali Linux. It will auto detect the file you give it with the -f flag as either being a text file with URLs on each new line. nmap xml output. or nessus xml output. The --timeout flag is completely optional. and lets you provide the max time to wait when trying to render and screenshot a web page.
        // Reference: https://github.com/FortyNorthSecurity/EyeWitness
        $string1 = /Witness\.py/ nocase ascii wide

    condition:
        any of them
}

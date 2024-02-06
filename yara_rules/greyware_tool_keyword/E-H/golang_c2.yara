rule golang_c2
{
    meta:
        description = "Detection patterns for the tool 'golang_c2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "golang_c2"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string1 = /http\:\/\/127\.0\.0\.1\:8000\/gate\.html/ nocase ascii wide

    condition:
        any of them
}

rule web_hacking_toolkit
{
    meta:
        description = "Detection patterns for the tool 'web-hacking-toolkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "web-hacking-toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A web hacking toolkit Docker image with GUI applications support.
        // Reference: https://github.com/signedsecurity/web-hacking-toolkit
        $string1 = /\sweb\-hacking\-toolkit\s/ nocase ascii wide
        // Description: A web hacking toolkit Docker image with GUI applications support.
        // Reference: https://github.com/signedsecurity/web-hacking-toolkit
        $string2 = /\/web\-hacking\-toolkit/ nocase ascii wide
        // Description: A web hacking toolkit Docker image with GUI applications support.
        // Reference: https://github.com/signedsecurity/web-hacking-toolkit
        $string3 = /web\-hacking\-toolkit\.git/ nocase ascii wide

    condition:
        any of them
}

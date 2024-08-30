rule go_secdump
{
    meta:
        description = "Detection patterns for the tool 'go-secdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "go-secdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string1 = /\.\/go\-secdump/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string2 = /\/go\-secdump\.git/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string3 = /\\go\-secdump/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string4 = /go\-secdump\s\-/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string5 = /go\-secdump\.exe/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string6 = /go\-secdump\-main/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string7 = /jfjallid\/go\-secdump/ nocase ascii wide

    condition:
        any of them
}

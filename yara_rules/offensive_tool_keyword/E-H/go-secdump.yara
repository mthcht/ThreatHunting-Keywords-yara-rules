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
        $string1 = /.{0,1000}\.\/go\-secdump.{0,1000}/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string2 = /.{0,1000}\/go\-secdump\.git.{0,1000}/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string3 = /.{0,1000}\\go\-secdump.{0,1000}/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string4 = /.{0,1000}go\-secdump\s\-.{0,1000}/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string5 = /.{0,1000}go\-secdump\.exe.{0,1000}/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string6 = /.{0,1000}go\-secdump\-main.{0,1000}/ nocase ascii wide
        // Description: Tool to remotely dump secrets from the Windows registry
        // Reference: https://github.com/jfjallid/go-secdump
        $string7 = /.{0,1000}jfjallid\/go\-secdump.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

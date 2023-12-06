rule anydesk
{
    meta:
        description = "Detection patterns for the tool 'anydesk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anydesk"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fake Anydesk distributed by discord - mars stealer
        // Reference: https://www.virustotal.com/gui/url/f83616f0f9cd2337ed40e22b0a675a99d58edf004b31645f56f28f020f5e4f46/detection
        $string1 = /discordapp\.com\/attachments\/.{0,1000}\/AnyDesk\.exe/ nocase ascii wide

    condition:
        any of them
}

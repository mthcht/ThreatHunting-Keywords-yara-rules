rule emkei_cz
{
    meta:
        description = "Detection patterns for the tool 'emkei.cz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "emkei.cz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Free online fake mailer with attachments
        // Reference: https://emkei.cz/
        $string1 = /https\:\/\/emkei\.cz\// nocase ascii wide

    condition:
        any of them
}

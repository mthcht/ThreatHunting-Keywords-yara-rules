rule pastebin
{
    meta:
        description = "Detection patterns for the tool 'pastebin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastebin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: pastebin raw access content - abused by malwares to retrieve payloads
        // Reference: pastebin.com
        $string1 = /pastebin\.com.{0,1000}\/raw\/.{0,1000}\s/ nocase ascii wide
        // Description: pastebin raw access content - abused by malwares to retrieve payloads
        // Reference: pastebin.com
        $string2 = /pastebin\.com.{0,1000}\/rw\// nocase ascii wide
        // Description: pastebin POST url - abused by malwares to exfiltrate informations
        // Reference: pastebin.com
        $string3 = /pastebin\.com.{0,1000}api\/api_post\.php/ nocase ascii wide

    condition:
        any of them
}

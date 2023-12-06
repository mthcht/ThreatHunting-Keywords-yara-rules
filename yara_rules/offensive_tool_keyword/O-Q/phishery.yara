rule phishery
{
    meta:
        description = "Detection patterns for the tool 'phishery' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "phishery"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Phishery is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. Phishery also provides the ability easily to inject the URL into a .docx Word document.
        // Reference: https://github.com/ryhanson/phishery
        $string1 = /phishery/ nocase ascii wide

    condition:
        any of them
}

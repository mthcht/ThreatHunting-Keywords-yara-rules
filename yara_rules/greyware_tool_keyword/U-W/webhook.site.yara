rule webhook_site
{
    meta:
        description = "Detection patterns for the tool 'webhook.site' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webhook.site"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: test HTTP webhooks with this handy tool that displays requests instantly - abused by attacker for payload callback confirmation
        // Reference: https://github.com/webhooksite/webhook.site
        $string1 = /\/webhook\.site\.git/ nocase ascii wide
        // Description: test HTTP webhooks with this handy tool that displays requests instantly - abused by attacker for payload callback confirmation
        // Reference: https://github.com/webhooksite/webhook.site
        $string2 = /\@email\.webhook\.site/ nocase ascii wide
        // Description: test HTTP webhooks with this handy tool that displays requests instantly - abused by attacker for payload callback confirmation
        // Reference: https://github.com/webhooksite/webhook.site
        $string3 = /https\:\/\/webhook\.site\/.{0,1000}\-.{0,1000}\-.{0,1000}\-/ nocase ascii wide
        // Description: test HTTP webhooks with this handy tool that displays requests instantly - abused by attacker for payload callback confirmation
        // Reference: https://github.com/webhooksite/webhook.site
        $string4 = /webhooksite\/webhook\.site/ nocase ascii wide
        // Description: test HTTP webhooks with this handy tool that displays requests instantly - abused by attacker for payload callback confirmation
        // Reference: https://github.com/webhooksite/webhook.site
        $string5 = /whcli\sforward\s\-\-token\=.{0,1000}\-.{0,1000}\-.{0,1000}\s\-\-target\=https\:\/\/localhost/ nocase ascii wide

    condition:
        any of them
}

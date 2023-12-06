rule Adblock_Office_VPN_Proxy_Server
{
    meta:
        description = "Detection patterns for the tool 'Adblock Office VPN Proxy Server' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adblock Office VPN Proxy Server"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1 = /lcmammnjlbmlbcaniggmlejfjpjagiia/ nocase ascii wide

    condition:
        any of them
}

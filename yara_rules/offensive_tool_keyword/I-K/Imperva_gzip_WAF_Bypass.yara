rule Imperva_gzip_WAF_Bypass
{
    meta:
        description = "Detection patterns for the tool 'Imperva_gzip_WAF_Bypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Imperva_gzip_WAF_Bypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Imperva Cloud WAF was vulnerable to a bypass that allows attackers to evade WAF rules when sending malicious HTTP POST payloads. such as log4j exploits. SQL injection. command execution. directory traversal. XXE. etc.
        // Reference: https://github.com/BishopFox/Imperva_gzip_WAF_Bypass
        $string1 = /\/Imperva_gzip_WAF_Bypass/ nocase ascii wide
        // Description: Imperva Cloud WAF was vulnerable to a bypass that allows attackers to evade WAF rules when sending malicious HTTP POST payloads. such as log4j exploits. SQL injection. command execution. directory traversal. XXE. etc.
        // Reference: https://github.com/BishopFox/Imperva_gzip_WAF_Bypass
        $string2 = /imperva_gzip\.py/ nocase ascii wide

    condition:
        any of them
}

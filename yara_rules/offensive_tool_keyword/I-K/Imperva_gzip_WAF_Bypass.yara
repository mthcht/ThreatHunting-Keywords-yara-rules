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
        $string1 = /.{0,1000}\/Imperva_gzip_WAF_Bypass.{0,1000}/ nocase ascii wide
        // Description: Imperva Cloud WAF was vulnerable to a bypass that allows attackers to evade WAF rules when sending malicious HTTP POST payloads. such as log4j exploits. SQL injection. command execution. directory traversal. XXE. etc.
        // Reference: https://github.com/BishopFox/Imperva_gzip_WAF_Bypass
        $string2 = /.{0,1000}imperva_gzip\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

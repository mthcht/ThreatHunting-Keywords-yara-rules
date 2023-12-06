rule security_onion
{
    meta:
        description = "Detection patterns for the tool 'security-onion' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "security-onion"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Security Onion is a free and open source Linux distribution for threat hunting. enterprise security monitoring. and log management. It includes Elasticsearch. Logstash. Kibana. Snort. Suricata. Bro. Wazuh. Sguil. Squert. NetworkMiner. and many other security tools. The easy-to-use Setup wizard allows you to build an army of distributed sensors for your enterprise in minutes
        // Reference: https://github.com/Security-Onion-Solutions/security-onion
        $string1 = /security\-onion/ nocase ascii wide

    condition:
        any of them
}

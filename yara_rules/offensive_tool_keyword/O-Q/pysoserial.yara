rule pysoserial
{
    meta:
        description = "Detection patterns for the tool 'pysoserial' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysoserial"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string1 = /\s\-c\s.{0,1000}\s\-o\spayload\.ser/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string2 = /\s\-\-command\s.{0,1000}\s\-\-output\spayload/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string3 = /\s\-p\sCommonsCollections1\s\-c\swhoami/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string4 = /\s\-\-payload\sCommonsCollections/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string5 = /\/Pysoserial\.git/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string6 = /generate_beanshell1/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string7 = /generate_jdk8u20/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string8 = /generate_mozillarhino1/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string9 = /generate_mozillarhino2/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string10 = /pysoserial\.py/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string11 = /Pysoserial\-main/ nocase ascii wide

    condition:
        any of them
}

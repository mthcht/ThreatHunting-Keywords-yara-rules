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
        $string1 = /.{0,1000}\s\-c\s.{0,1000}\s\-o\spayload\.ser.{0,1000}/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string2 = /.{0,1000}\s\-\-command\s.{0,1000}\s\-\-output\spayload.{0,1000}/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string3 = /.{0,1000}\s\-p\sCommonsCollections1\s\-c\swhoami.{0,1000}/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string4 = /.{0,1000}\s\-\-payload\sCommonsCollections.{0,1000}/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string5 = /.{0,1000}\/Pysoserial\.git.{0,1000}/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string6 = /.{0,1000}generate_beanshell1.{0,1000}/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string7 = /.{0,1000}generate_jdk8u20.{0,1000}/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string8 = /.{0,1000}generate_mozillarhino1.{0,1000}/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string9 = /.{0,1000}generate_mozillarhino2.{0,1000}/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string10 = /.{0,1000}pysoserial\.py.{0,1000}/ nocase ascii wide
        // Description: Python-based proof-of-concept tool for generating payloads that utilize unsafe Java object deserialization.
        // Reference: https://github.com/aStrowxyu/Pysoserial
        $string11 = /.{0,1000}Pysoserial\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

rule SamDumpCable
{
    meta:
        description = "Detection patterns for the tool 'SamDumpCable' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SamDumpCable"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dump users sam and system hive and exfiltrate them
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SamDumpCable
        $string1 = /1337OMGsam/ nocase ascii wide
        // Description: Dump users sam and system hive and exfiltrate them
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SamDumpCable
        $string2 = /1337OMGsys/ nocase ascii wide
        // Description: Dump users sam and system hive and exfiltrate them
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SamDumpCable
        $string3 = /cgBlAGcAIABzAGEAdgBlACAAaABrAGwAbQBcAHMAYQBtACAAMQ/ nocase ascii wide
        // Description: Dump users sam and system hive and exfiltrate them
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SamDumpCable
        $string4 = /OMGdump\.zip/ nocase ascii wide
        // Description: Dump users sam and system hive and exfiltrate them
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SamDumpCable
        $string5 = /reg\ssave\shklm\\sam\s1337/ nocase ascii wide
        // Description: Dump users sam and system hive and exfiltrate them
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SamDumpCable
        $string6 = /reg\ssave\shklm\\system\s1337/ nocase ascii wide

    condition:
        any of them
}

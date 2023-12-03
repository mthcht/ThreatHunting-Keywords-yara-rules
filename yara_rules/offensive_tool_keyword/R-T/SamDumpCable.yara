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
        $string1 = /.{0,1000}1337OMGsam.{0,1000}/ nocase ascii wide
        // Description: Dump users sam and system hive and exfiltrate them
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SamDumpCable
        $string2 = /.{0,1000}1337OMGsys.{0,1000}/ nocase ascii wide
        // Description: Dump users sam and system hive and exfiltrate them
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SamDumpCable
        $string3 = /.{0,1000}cgBlAGcAIABzAGEAdgBlACAAaABrAGwAbQBcAHMAYQBtACAAMQ.{0,1000}/ nocase ascii wide
        // Description: Dump users sam and system hive and exfiltrate them
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SamDumpCable
        $string4 = /.{0,1000}OMGdump\.zip.{0,1000}/ nocase ascii wide
        // Description: Dump users sam and system hive and exfiltrate them
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SamDumpCable
        $string5 = /.{0,1000}reg\ssave\shklm\\sam\s1337.{0,1000}/ nocase ascii wide
        // Description: Dump users sam and system hive and exfiltrate them
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SamDumpCable
        $string6 = /.{0,1000}reg\ssave\shklm\\system\s1337.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

rule dpapi_py
{
    meta:
        description = "Detection patterns for the tool 'dpapi.py' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dpapi.py"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: the command is used to extract the Data Protection API (DPAPI) backup keys from a target system. DPAPI is a Windows API that provides data protection services to secure sensitive data. such as private keys. passwords. and other secrets. By obtaining the DPAPI backup keys. an attacker can potentially decrypt sensitive data stored on the target system or impersonate users. gaining unauthorized access to other systems and resources.
        // Reference: N/A
        $string1 = /dpapi\.py\sbackupkeys\s\-t\s.{0,1000}\/.{0,1000}\@/ nocase ascii wide

    condition:
        any of them
}

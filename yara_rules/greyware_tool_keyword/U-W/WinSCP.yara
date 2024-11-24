rule WinSCP
{
    meta:
        description = "Detection patterns for the tool 'WinSCP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinSCP"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SFTP connexion with winscp - legit tool abused by threat actors to exfiltrate data
        // Reference: N/A
        $string1 = /\\CurrentVersion\\Uninstall\\winscp3_is1/ nocase ascii wide
        // Description: SFTP connexion with winscp - legit tool abused by threat actors to exfiltrate data
        // Reference: N/A
        $string2 = /\\Program\sFiles\\WinSCP/ nocase ascii wide
        // Description: SFTP connexion with winscp - legit tool abused by threat actors to exfiltrate data
        // Reference: N/A
        $string3 = /\\SOFTWARE\\Martin\sPrikryl\\WinSCP\s2\\/ nocase ascii wide
        // Description: SFTP connexion with winscp - legit tool abused by threat actors to exfiltrate data
        // Reference: N/A
        $string4 = /Temp.{0,1000}_WinSCP\-\-Portable\.zip/ nocase ascii wide
        // Description: SFTP connexion with winscp - legit tool abused by threat actors to exfiltrate data
        // Reference: N/A
        $string5 = /winscp\.com\s\/command\s\\"open\ssftp\:\/\// nocase ascii wide

    condition:
        any of them
}

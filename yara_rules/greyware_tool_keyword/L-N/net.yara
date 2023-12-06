rule net
{
    meta:
        description = "Detection patterns for the tool 'net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Enumerate local accounts
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string1 = /\\net\.exe\"\saccounts/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string2 = /\\net\.exe.{0,1000}\slocalgroup\sadmin/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string3 = /\\net\.exe.{0,1000}\ssessions/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string4 = /\\net\.exe.{0,1000}\sview\s.{0,1000}\/domain/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string5 = /\\net1\ssessions/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string6 = /net\sgroup\s\"Domain\sAdmins\"\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string7 = /net\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string8 = /net\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string9 = /net\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string10 = /net\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Query Domain Comtrollers Computers in the current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string11 = /net\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string12 = /net\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string13 = /net\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string14 = /net\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string15 = /net\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string16 = /net\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string17 = /net\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string18 = /net\sgroup\s\/domain\s.{0,1000}Domain\sAdmins/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string19 = /net\sgroup\sadministrators\s\/domain/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string20 = /net\slocalgroup\sadmin/ nocase ascii wide
        // Description: VoidCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string21 = /net\sstop\sMSSQL\$CONTOSO1/ nocase ascii wide
        // Description: manipulation of an hidden local account with the net command
        // Reference: N/A
        $string22 = /net\suser\s.{0,1000}\$.{0,1000}\s\// nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string23 = /net\sview\s\/all\s\/domain/ nocase ascii wide
        // Description: adding a user to a privileged group. This action can be used by adversaries to maintain unauthorized access or escalate privileges within the targeted environment.
        // Reference: N/A
        $string24 = /net.{0,1000}\sgroup\sAdministrator.{0,1000}\s\/add\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string25 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string26 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string27 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string28 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string29 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string30 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string31 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string32 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string33 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string34 = /net\.exe.{0,1000}\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string35 = /net1\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string36 = /net1\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string37 = /net1\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string38 = /net1\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string39 = /net1\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string40 = /net1\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string41 = /net1\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string42 = /net1\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string43 = /net1\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string44 = /net1\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string45 = /net1\slocalgroup\sadmin/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string46 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string47 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string48 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string49 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string50 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string51 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string52 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string53 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string54 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string55 = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide

    condition:
        any of them
}

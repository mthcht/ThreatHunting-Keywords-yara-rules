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
        $string1 = /.{0,1000}\\net\.exe\"\saccounts.{0,1000}/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string2 = /.{0,1000}\\net\.exe.{0,1000}\slocalgroup\sadmin.{0,1000}/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string3 = /.{0,1000}\\net\.exe.{0,1000}\ssessions.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string4 = /.{0,1000}\\net\.exe.{0,1000}\sview\s.{0,1000}\/domain.{0,1000}/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string5 = /.{0,1000}\\net1\ssessions.{0,1000}/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string6 = /.{0,1000}net\sgroup\s\"Domain\sAdmins\"\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string7 = /.{0,1000}net\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string8 = /.{0,1000}net\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string9 = /.{0,1000}net\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string10 = /.{0,1000}net\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: Query Domain Comtrollers Computers in the current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string11 = /.{0,1000}net\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string12 = /.{0,1000}net\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string13 = /.{0,1000}net\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string14 = /.{0,1000}net\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string15 = /.{0,1000}net\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string16 = /.{0,1000}net\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string17 = /.{0,1000}net\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string18 = /.{0,1000}net\sgroup\s\/domain\s.{0,1000}Domain\sAdmins.{0,1000}/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string19 = /.{0,1000}net\sgroup\sadministrators\s\/domain.{0,1000}/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string20 = /.{0,1000}net\slocalgroup\sadmin.{0,1000}/ nocase ascii wide
        // Description: VoidCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string21 = /.{0,1000}net\sstop\sMSSQL\$CONTOSO1.{0,1000}/ nocase ascii wide
        // Description: manipulation of an hidden local account with the net command
        // Reference: N/A
        $string22 = /.{0,1000}net\suser\s.{0,1000}\$.{0,1000}\s\/.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string23 = /.{0,1000}net\sview\s\/all\s\/domain.{0,1000}/ nocase ascii wide
        // Description: adding a user to a privileged group. This action can be used by adversaries to maintain unauthorized access or escalate privileges within the targeted environment.
        // Reference: N/A
        $string24 = /.{0,1000}net.{0,1000}\sgroup\sAdministrator.{0,1000}\s\/add\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string25 = /.{0,1000}net\.exe.{0,1000}\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string26 = /.{0,1000}net\.exe.{0,1000}\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string27 = /.{0,1000}net\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string28 = /.{0,1000}net\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string29 = /.{0,1000}net\.exe.{0,1000}\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string30 = /.{0,1000}net\.exe.{0,1000}\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string31 = /.{0,1000}net\.exe.{0,1000}\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string32 = /.{0,1000}net\.exe.{0,1000}\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string33 = /.{0,1000}net\.exe.{0,1000}\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string34 = /.{0,1000}net\.exe.{0,1000}\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string35 = /.{0,1000}net1\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string36 = /.{0,1000}net1\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string37 = /.{0,1000}net1\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string38 = /.{0,1000}net1\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string39 = /.{0,1000}net1\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string40 = /.{0,1000}net1\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string41 = /.{0,1000}net1\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string42 = /.{0,1000}net1\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string43 = /.{0,1000}net1\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string44 = /.{0,1000}net1\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string45 = /.{0,1000}net1\slocalgroup\sadmin.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string46 = /.{0,1000}net1\.exe.{0,1000}\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string47 = /.{0,1000}net1\.exe.{0,1000}\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string48 = /.{0,1000}net1\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string49 = /.{0,1000}net1\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string50 = /.{0,1000}net1\.exe.{0,1000}\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string51 = /.{0,1000}net1\.exe.{0,1000}\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string52 = /.{0,1000}net1\.exe.{0,1000}\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string53 = /.{0,1000}net1\.exe.{0,1000}\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string54 = /.{0,1000}net1\.exe.{0,1000}\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string55 = /.{0,1000}net1\.exe.{0,1000}\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

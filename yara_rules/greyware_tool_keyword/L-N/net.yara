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
        $string2 = /\\net\.exe.*\slocalgroup\sadmin/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string3 = /\\net\.exe.*\ssessions/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string4 = /\\net\.exe.*\sview\s.*\/domain/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string5 = /\\net1\ssessions/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string6 = /net\sgroup\s\"Domain\sAdmins\"\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string7 = /net\sgroup\s.*Account\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string8 = /net\sgroup\s.*Backup\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string9 = /net\sgroup\s.*Domain\sComputers.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string10 = /net\sgroup\s.*Domain\sControllers.*\s\/domain/ nocase ascii wide
        // Description: Query Domain Comtrollers Computers in the current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string11 = /net\sgroup\s.*Domain\sControllers.*\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string12 = /net\sgroup\s.*Enterprise\sAdmins.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string13 = /net\sgroup\s.*Exchange\sTrusted\sSubsystem.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string14 = /net\sgroup\s.*Microsoft\sExchange\sServers.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string15 = /net\sgroup\s.*Print\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string16 = /net\sgroup\s.*Schema\sAdmins.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string17 = /net\sgroup\s.*Server\sOperators.*\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string18 = /net\sgroup\s\/domain\s.*Domain\sAdmins/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string19 = /net\sgroup\sadministrators\s\/domain/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string20 = /net\slocalgroup\sadmin/ nocase ascii wide
        // Description: manipulation of an hidden local account with the net command
        // Reference: N/A
        $string21 = /net\suser\s.*\$.*\s\// nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string22 = /net\sview\s\/all\s\/domain/ nocase ascii wide
        // Description: adding a user to a privileged group. This action can be used by adversaries to maintain unauthorized access or escalate privileges within the targeted environment.
        // Reference: N/A
        $string23 = /net.*\sgroup\sAdministrator.*\s\/add\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string24 = /net\.exe.*\sgroup\s.*Account\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string25 = /net\.exe.*\sgroup\s.*Backup\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string26 = /net\.exe.*\sgroup\s.*Domain\sComputers.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string27 = /net\.exe.*\sgroup\s.*Domain\sControllers.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string28 = /net\.exe.*\sgroup\s.*Enterprise\sAdmins.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string29 = /net\.exe.*\sgroup\s.*Exchange\sTrusted\sSubsystem.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string30 = /net\.exe.*\sgroup\s.*Microsoft\sExchange\sServers.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string31 = /net\.exe.*\sgroup\s.*Print\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string32 = /net\.exe.*\sgroup\s.*Schema\sAdmins.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string33 = /net\.exe.*\sgroup\s.*Server\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string34 = /net1\sgroup\s.*Account\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string35 = /net1\sgroup\s.*Backup\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string36 = /net1\sgroup\s.*Domain\sComputers.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string37 = /net1\sgroup\s.*Domain\sControllers.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string38 = /net1\sgroup\s.*Enterprise\sAdmins.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string39 = /net1\sgroup\s.*Exchange\sTrusted\sSubsystem.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string40 = /net1\sgroup\s.*Microsoft\sExchange\sServers.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string41 = /net1\sgroup\s.*Print\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string42 = /net1\sgroup\s.*Schema\sAdmins.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string43 = /net1\sgroup\s.*Server\sOperators.*\s\/domain/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string44 = /net1\slocalgroup\sadmin/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string45 = /net1\.exe.*\sgroup\s.*Account\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string46 = /net1\.exe.*\sgroup\s.*Backup\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string47 = /net1\.exe.*\sgroup\s.*Domain\sComputers.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string48 = /net1\.exe.*\sgroup\s.*Domain\sControllers.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string49 = /net1\.exe.*\sgroup\s.*Enterprise\sAdmins.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string50 = /net1\.exe.*\sgroup\s.*Exchange\sTrusted\sSubsystem.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string51 = /net1\.exe.*\sgroup\s.*Microsoft\sExchange\sServers.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string52 = /net1\.exe.*\sgroup\s.*Print\sOperators.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string53 = /net1\.exe.*\sgroup\s.*Schema\sAdmins.*\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string54 = /net1\.exe.*\sgroup\s.*Server\sOperators.*\s\/domain/ nocase ascii wide

    condition:
        any of them
}
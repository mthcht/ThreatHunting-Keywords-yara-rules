rule Rubeus
{
    meta:
        description = "Detection patterns for the tool 'Rubeus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rubeus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string1 = /\s\/altservice:ldap\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string2 = /\s\/asrepkey/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string3 = /\s\/createnetonly:.{0,1000}cmd\.exe/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string4 = /\s\/createnetonly:.{0,1000}cmd\.exe/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string5 = /\s\/credpassword/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string6 = /\s\/creduser:.{0,1000}\s\/credpassword:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string7 = /\s\/impersonateuser:.{0,1000}\s\/msdsspn:.{0,1000}\s\/ptt/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string8 = /\s\/ldap\s.{0,1000}\s\/printcmd/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string9 = /\s\/ldapfilter:\'admincount\=1\'/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string10 = /\s\/nofullpacsig\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string11 = /\s\/outfile:.{0,1000}\s\/spn:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string12 = /\s\/outfile:.{0,1000}\s\/spns:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string13 = /\s\/pwdsetafter:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string14 = /\s\/pwdsetbefore:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string15 = /\s\/rc4opsec\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string16 = /\s\/s4uproxytarget/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string17 = /\s\/s4utransitedservices/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string18 = /\s\/service:krbtgt\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string19 = /\s\/simple\s.{0,1000}\s\/spn/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string20 = /\s\/ticket\s.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string21 = /\s\/ticket:.{0,1000}\s\/autoenterprise\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string22 = /\s\/ticket:.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string23 = /\s\/usetgtdeleg\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string24 = /\sasktgs\s.{0,1000}\s\/ticket:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string25 = /\sasktgs\s.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string26 = /\sasktgs\s\/ticket:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string27 = /\sasktgt\s.{0,1000}\s\/service:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string28 = /\sasktgt\s\/user\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string29 = /\sasktht\s\/user:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string30 = /\sasreproast\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string31 = /\sbrute\s.{0,1000}\s\/password/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string32 = /\schangepw\s.{0,1000}\s\/ticket:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string33 = /\sdiamond\s.{0,1000}\s\s\/certificate:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string34 = /\sdiamond\s\/tgtdeleg\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string35 = /\sdiamond\s\/user:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string36 = /\sdump\s.{0,1000}\s\/service:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string37 = /\sgolden\s.{0,1000}\s\/badpwdcount/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string38 = /\sgolden\s.{0,1000}\s\/ldap\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string39 = /\sgolden\s.{0,1000}\s\/user:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string40 = /\sharvest\s.{0,1000}\s\/monitorinterval:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string41 = /\skerberoast\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string42 = /\skerberoast\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string43 = /\sklist\s.{0,1000}\s\/service:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string44 = /\smonitor\s\/interval:.{0,1000}\s\/filteruser:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string45 = /\spreauthscan\s\/users:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string46 = /\sptt\s\/ticket:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string47 = /\srenew\s.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string48 = /\srenew\s.{0,1000}\/ticket:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string49 = /\ss4u\s.{0,1000}\s\/bronzebit/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string50 = /\ss4u\s.{0,1000}\s\/nopac/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string51 = /\ss4u\s.{0,1000}\s\/ticket:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string52 = /\ss4u\s.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string53 = /\ss4u\s.{0,1000}\/rc4:.{0,1000}\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string54 = /\ssilver\s.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string55 = /\ssilver\s.{0,1000}\s\/ldap\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string56 = /\ssilver\s.{0,1000}\s\/passlastset\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string57 = /\ssilver\s.{0,1000}\s\/service:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string58 = /\stgssub\s.{0,1000}\s\/ticket:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string59 = /\stgtdeleg\s\/nowrap/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string60 = /\stgtdeleg\s\/target:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string61 = /\.exe\shash\s\/password:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string62 = /\.exe\sptt\s\/ticket:.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string63 = /\/Bruteforcer\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string64 = /\/format:hashcat/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string65 = /\/Rubeus/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string66 = /\/Rubeus\.git/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string67 = /\/Rubeus\// nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string68 = /\\Bruteforcer\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string69 = /\\Rubeus\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string70 = /\\Rubeus\\/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string71 = /658C8B7F\-3664\-4A95\-9572\-A3E5871DFC06/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string72 = /658C8B7F\-3664\-4A95\-9572\-A3E5871DFC06/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string73 = /66e0681a500c726ed52e5ea9423d2654/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string74 = /asrep2kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string75 = /Asreproast\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string76 = /Commands\/Brute\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string77 = /Commands\/Createnetonly\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string78 = /Commands\/Logonsession\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string79 = /Commands\/Preauthscan\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string80 = /Commands\/Silver\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string81 = /Domain\/CommandCollection/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string82 = /GhostPack\/Rubeus/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string83 = /kerberoast\s\// nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string84 = /Kerberoast\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string85 = /lib\/ForgeTicket\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string86 = /lib\/S4U\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string87 = /Rubeus.{0,1000}currentluid/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string88 = /Rubeus.{0,1000}harvest/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string89 = /Rubeus.{0,1000}logonsession/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string90 = /Rubeus.{0,1000}monitor/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string91 = /Rubeus\.Commands/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string92 = /Rubeus\.exe/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string93 = /Rubeus\.git/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string94 = /Rubeus\.Kerberos/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string95 = /Rubeus\.lib/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string96 = /Rubeus\-master/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string97 = /ticket\.kirbi/ nocase ascii wide

    condition:
        any of them
}

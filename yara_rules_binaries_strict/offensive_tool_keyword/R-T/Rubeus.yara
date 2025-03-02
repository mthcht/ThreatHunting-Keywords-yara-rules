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
        $string1 = " /altservice:ldap " nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string2 = " /asrepkey" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string3 = /\s\/createnetonly\:.{0,100}cmd\.exe/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string4 = /\s\/createnetonly\:.{0,100}cmd\.exe/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string5 = " /credpassword" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string6 = /\s\/creduser\:.{0,100}\s\/credpassword\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string7 = /\s\/impersonateuser\:.{0,100}\s\/msdsspn\:.{0,100}\s\/ptt/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string8 = /\s\/ldap\s.{0,100}\s\/printcmd/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string9 = " /ldapfilter:'admincount=1'" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string10 = " /nofullpacsig " nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string11 = /\s\/outfile\:.{0,100}\s\/spn\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string12 = /\s\/outfile\:.{0,100}\s\/spns\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string13 = " /pwdsetafter:" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string14 = " /pwdsetbefore:" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string15 = " /rc4opsec " nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string16 = " /s4uproxytarget" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string17 = " /s4utransitedservices" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string18 = " /service:krbtgt " nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string19 = /\s\/simple\s.{0,100}\s\/spn/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string20 = /\s\/ticket\s.{0,100}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string21 = /\s\/ticket\:.{0,100}\s\/autoenterprise\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string22 = /\s\/ticket\:.{0,100}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string23 = " /usetgtdeleg " nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string24 = /\sasktgs\s.{0,100}\s\/ticket\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string25 = /\sasktgs\s.{0,100}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string26 = " asktgs /ticket:" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string27 = /\sasktgt\s.{0,100}\s\/service\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string28 = " asktgt /user " nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string29 = " asktht /user:" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string30 = " asreproast " nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string31 = /\sbrute\s.{0,100}\s\/password/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string32 = /\schangepw\s.{0,100}\s\/ticket\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string33 = /\sdiamond\s.{0,100}\s\/certificate\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string34 = " diamond /tgtdeleg " nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string35 = " diamond /user:" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string36 = /\sdump\s.{0,100}\s\/service\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string37 = /\sgolden\s.{0,100}\s\/badpwdcount/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string38 = /\sgolden\s.{0,100}\s\/ldap\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string39 = /\sgolden\s.{0,100}\s\/user\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string40 = /\sharvest\s.{0,100}\s\/monitorinterval\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string41 = " kerberoast " nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string42 = " kerberoast " nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string43 = /\sklist\s.{0,100}\s\/service\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string44 = /\smonitor\s\/interval\:.{0,100}\s\/filteruser\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string45 = " preauthscan /users:" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string46 = " ptt /ticket:" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string47 = /\srenew\s.{0,100}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string48 = /\srenew\s.{0,100}\/ticket\:/ nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string49 = /\sRubeus\.dll/ nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string50 = /\sRubeus\.ps1/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string51 = /\ss4u\s.{0,100}\s\/bronzebit/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string52 = /\ss4u\s.{0,100}\s\/nopac/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string53 = /\ss4u\s.{0,100}\s\/ticket\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string54 = /\ss4u\s.{0,100}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string55 = /\ss4u\s.{0,100}\/rc4\:.{0,100}\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string56 = /\ssilver\s.{0,100}\s\/domain/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string57 = /\ssilver\s.{0,100}\s\/ldap\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string58 = /\ssilver\s.{0,100}\s\/passlastset\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string59 = /\ssilver\s.{0,100}\s\/service\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string60 = /\stgssub\s.{0,100}\s\/ticket\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string61 = " tgtdeleg /nowrap" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string62 = " tgtdeleg /target:" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://x.com/_RastaMouse/status/1747636529613197757
        $string63 = "\"User32LogonProcesss\"" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string64 = /\(msds\-supportedencryptiontypes\=0\)\(msds\-supportedencryptiontypes\:1\.2\.840\.113556\.1\.4\.803\:\=4\)\)\)/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string65 = /\.exe\sdump\s\/luid\:.{0,100}\s\/service\:krbtgt/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string66 = /\.exe\shash\s\/password\:/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string67 = /\.exe\sptt\s\/ticket\:.{0,100}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string68 = /\/Bruteforcer\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string69 = "/format:hashcat" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string70 = "/Rubeus" nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string71 = /\/Rubeus\.dll/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string72 = /\/Rubeus\.exe/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string73 = /\/Rubeus\.git/ nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string74 = /\/Rubeus\.ps1/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string75 = "/Rubeus/" nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string76 = /\/Rubeus\-Rundll32\.git/ nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string77 = "/Rubeus-Rundll32/" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string78 = /\\Bruteforcer\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string79 = /\\Rubeus\./ nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string80 = /\\Rubeus\.dll/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string81 = /\\Rubeus\.exe/ nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string82 = /\\Rubeus\.ps1/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string83 = /\\Rubeus\\/ nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string84 = /\\Rubeus\-Rundll32\\/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://x.com/_RastaMouse/status/1747636529613197757
        $string85 = ">User32LogonProcesss<" nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string86 = "3ae0b0ec554f725076ca89389d9a3523e503a24248ee8a9b342f68c156e77b12" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string87 = "658C8B7F-3664-4A95-9572-A3E5871DFC06" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string88 = "658C8B7F-3664-4A95-9572-A3E5871DFC06" nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string89 = "658C8B7F-3664-4A95-9572-A3E5871DFC06" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string90 = "66e0681a500c726ed52e5ea9423d2654" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string91 = "asrep2kirbi" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string92 = /Asreproast\./ nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string93 = /cmd\.exe\'\ssuccessfully\screated\swith\sLOGON_TYPE\s\=\s9/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string94 = /Commands\/Brute\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string95 = /Commands\/Createnetonly\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string96 = /Commands\/Logonsession\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string97 = /Commands\/Preauthscan\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string98 = /Commands\/Silver\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string99 = "Domain/CommandCollection" nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string100 = "e415296f956351bc4060d03fa52512415f353e26236b7fd97642f7ef608ca4e9" nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string101 = "e8ddad70f68375dbf38d0e8550acf1e53f5382e0bf9a0ee8f02f8b1c6222db81" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string102 = "GhostPack/Rubeus" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string103 = "kerberoast /" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string104 = /Kerberoast\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string105 = /lib\/ForgeTicket\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string106 = /lib\/S4U\./ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string107 = "namespace Rubeus" nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string108 = /Rubeus.{0,100}currentluid/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string109 = /Rubeus.{0,100}harvest/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string110 = /Rubeus.{0,100}logonsession/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string111 = /Rubeus.{0,100}monitor/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string112 = /Rubeus\.Commands/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string113 = /Rubeus\.exe/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string114 = /Rubeus\.git/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string115 = /Rubeus\.Kerberos/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string116 = /Rubeus\.lib/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string117 = "Rubeus-master" nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string118 = /rundll32\s.{0,100}RunRubeus/ nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string119 = "rvrsh3ll/Rubeus-Rundll32" nocase ascii wide
        // Description: Run Rubeus via Rundll32 (potential application whitelisting bypass technique)
        // Reference: https://github.com/rvrsh3ll/Rubeus-Rundll32
        $string120 = /Temp\\\\rubeus/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string121 = /ticket\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string122 = /using\sRubeus\.Domain\;/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}

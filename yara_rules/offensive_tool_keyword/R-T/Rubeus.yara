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
        $string1 = /.{0,1000}\s\/altservice:ldap\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string2 = /.{0,1000}\s\/asrepkey.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string3 = /.{0,1000}\s\/createnetonly:.{0,1000}cmd\.exe.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string4 = /.{0,1000}\s\/createnetonly:.{0,1000}cmd\.exe.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string5 = /.{0,1000}\s\/credpassword.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string6 = /.{0,1000}\s\/creduser:.{0,1000}\s\/credpassword:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string7 = /.{0,1000}\s\/impersonateuser:.{0,1000}\s\/msdsspn:.{0,1000}\s\/ptt.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string8 = /.{0,1000}\s\/ldap\s.{0,1000}\s\/printcmd.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string9 = /.{0,1000}\s\/ldapfilter:\'admincount\=1\'.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string10 = /.{0,1000}\s\/nofullpacsig\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string11 = /.{0,1000}\s\/outfile:.{0,1000}\s\/spn:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string12 = /.{0,1000}\s\/outfile:.{0,1000}\s\/spns:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string13 = /.{0,1000}\s\/pwdsetafter:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string14 = /.{0,1000}\s\/pwdsetbefore:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string15 = /.{0,1000}\s\/rc4opsec\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string16 = /.{0,1000}\s\/s4uproxytarget.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string17 = /.{0,1000}\s\/s4utransitedservices.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string18 = /.{0,1000}\s\/service:krbtgt\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string19 = /.{0,1000}\s\/simple\s.{0,1000}\s\/spn.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string20 = /.{0,1000}\s\/ticket\s.{0,1000}\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string21 = /.{0,1000}\s\/ticket:.{0,1000}\s\/autoenterprise\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string22 = /.{0,1000}\s\/ticket:.{0,1000}\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string23 = /.{0,1000}\s\/usetgtdeleg\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string24 = /.{0,1000}\sasktgs\s.{0,1000}\s\/ticket:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string25 = /.{0,1000}\sasktgs\s.{0,1000}\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string26 = /.{0,1000}\sasktgs\s\/ticket:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string27 = /.{0,1000}\sasktgt\s.{0,1000}\s\/service:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string28 = /.{0,1000}\sasktgt\s\/user\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string29 = /.{0,1000}\sasktht\s\/user:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string30 = /.{0,1000}\sasreproast\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string31 = /.{0,1000}\sbrute\s.{0,1000}\s\/password.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string32 = /.{0,1000}\schangepw\s.{0,1000}\s\/ticket:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string33 = /.{0,1000}\sdiamond\s.{0,1000}\s\s\/certificate:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string34 = /.{0,1000}\sdiamond\s\/tgtdeleg\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string35 = /.{0,1000}\sdiamond\s\/user:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string36 = /.{0,1000}\sdump\s.{0,1000}\s\/service:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string37 = /.{0,1000}\sgolden\s.{0,1000}\s\/badpwdcount.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string38 = /.{0,1000}\sgolden\s.{0,1000}\s\/ldap\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string39 = /.{0,1000}\sgolden\s.{0,1000}\s\/user:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string40 = /.{0,1000}\sharvest\s.{0,1000}\s\/monitorinterval:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string41 = /.{0,1000}\skerberoast\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string42 = /.{0,1000}\skerberoast\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string43 = /.{0,1000}\sklist\s.{0,1000}\s\/service:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string44 = /.{0,1000}\smonitor\s\/interval:.{0,1000}\s\/filteruser:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string45 = /.{0,1000}\spreauthscan\s\/users:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string46 = /.{0,1000}\sptt\s\/ticket:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string47 = /.{0,1000}\srenew\s.{0,1000}\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string48 = /.{0,1000}\srenew\s.{0,1000}\/ticket:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string49 = /.{0,1000}\ss4u\s.{0,1000}\s\/bronzebit.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string50 = /.{0,1000}\ss4u\s.{0,1000}\s\/nopac.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string51 = /.{0,1000}\ss4u\s.{0,1000}\s\/ticket:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string52 = /.{0,1000}\ss4u\s.{0,1000}\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string53 = /.{0,1000}\ss4u\s.{0,1000}\/rc4:.{0,1000}\s/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string54 = /.{0,1000}\ssilver\s.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string55 = /.{0,1000}\ssilver\s.{0,1000}\s\/ldap\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string56 = /.{0,1000}\ssilver\s.{0,1000}\s\/passlastset\s.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string57 = /.{0,1000}\ssilver\s.{0,1000}\s\/service:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string58 = /.{0,1000}\stgssub\s.{0,1000}\s\/ticket:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string59 = /.{0,1000}\stgtdeleg\s\/nowrap.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string60 = /.{0,1000}\stgtdeleg\s\/target:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string61 = /.{0,1000}\.exe\shash\s\/password:.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string62 = /.{0,1000}\.exe\sptt\s\/ticket:.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string63 = /.{0,1000}\/Bruteforcer\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string64 = /.{0,1000}\/format:hashcat.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string65 = /.{0,1000}\/Rubeus.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string66 = /.{0,1000}\/Rubeus\.git.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string67 = /.{0,1000}\/Rubeus\/.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string68 = /.{0,1000}\\Bruteforcer\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string69 = /.{0,1000}\\Rubeus\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string70 = /.{0,1000}\\Rubeus\\.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string71 = /.{0,1000}658C8B7F\-3664\-4A95\-9572\-A3E5871DFC06.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string72 = /.{0,1000}658C8B7F\-3664\-4A95\-9572\-A3E5871DFC06.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string73 = /.{0,1000}66e0681a500c726ed52e5ea9423d2654.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string74 = /.{0,1000}asrep2kirbi.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string75 = /.{0,1000}Asreproast\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string76 = /.{0,1000}Commands\/Brute\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string77 = /.{0,1000}Commands\/Createnetonly\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string78 = /.{0,1000}Commands\/Logonsession\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string79 = /.{0,1000}Commands\/Preauthscan\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string80 = /.{0,1000}Commands\/Silver\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string81 = /.{0,1000}Domain\/CommandCollection.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string82 = /.{0,1000}GhostPack\/Rubeus.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string83 = /.{0,1000}kerberoast\s\/.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string84 = /.{0,1000}Kerberoast\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string85 = /.{0,1000}lib\/ForgeTicket\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string86 = /.{0,1000}lib\/S4U\..{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string87 = /.{0,1000}Rubeus.{0,1000}currentluid.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string88 = /.{0,1000}Rubeus.{0,1000}harvest.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string89 = /.{0,1000}Rubeus.{0,1000}logonsession.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string90 = /.{0,1000}Rubeus.{0,1000}monitor.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string91 = /.{0,1000}Rubeus\.Commands.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string92 = /.{0,1000}Rubeus\.exe.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string93 = /.{0,1000}Rubeus\.git.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string94 = /.{0,1000}Rubeus\.Kerberos.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string95 = /.{0,1000}Rubeus\.lib.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string96 = /.{0,1000}Rubeus\-master.{0,1000}/ nocase ascii wide
        // Description: Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUXs MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
        // Reference: https://github.com/GhostPack/Rubeus
        $string97 = /.{0,1000}ticket\.kirbi.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

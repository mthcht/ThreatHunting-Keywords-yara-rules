rule impacket
{
    meta:
        description = "Detection patterns for the tool 'impacket' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impacket"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string1 = /\s\-dc\-ip\s.{0,1000}\s\s\-so\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string2 = /\s\-dc\-ip\s.{0,1000}\s\-computer\-pass\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string3 = /\s\-dc\-ip\s.{0,1000}\s\-impersonate\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string4 = /\s\-dc\-ip\s.{0,1000}\s\-target\-ip\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string5 = /\s\-force\-forwardable/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string6 = /\s\-hashes\s.{0,1000}\s\-spn\s.{0,1000}\s\-impersonate\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string7 = /\simpacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string8 = /\simpacket\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string9 = /\s\-impersonate.{0,1000}\s\-hashes/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string10 = /\s\-just\-dc\-ntlm\s\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string11 = /\s\-just\-dc\-user\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string12 = /\s\-k\s\-request\-user\s.{0,1000}\s\-dc\-ip/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string13 = /\sLMHASH\:NTHASH/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string14 = /\s\-no\-pass\s\-usersfile\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string15 = /\s\-ntds\s.{0,1000}\.dit\s.{0,1000}\-system\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string16 = /\s\-nthash\s.{0,1000}\s\-domain\-sid\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string17 = /\sntlm\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string18 = /\sPrincipalsAllowedToDelegateToAccount\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string19 = /\s\-sam\s.{0,1000}\s\-system\s.{0,1000}\s\-security\s.{0,1000}\sLOCAL\s\>\s.{0,1000}\.out/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string20 = /\s\-spn\scifs\/.{0,1000}\s\-hashes/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string21 = /\s\-system\sSYSTEM\s\-ntds\sNTDS\.dit\sLOCAL/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string22 = /\s\-system\sSYSTEM\s\-ntds\sNTDS\.dit\s\-outputfile/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string23 = /\s\-target\-domain\s.{0,1000}\s\-outputfile\s.{0,1000}\s\-no\-pass/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string24 = /\.py\s.{0,1000}\s\-k\s\-no\-pass/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string25 = /\/atexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string26 = /\/attacks\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string27 = /\/exchanger\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string28 = /\/getST\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string29 = /\/impacket\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string30 = /\/impacket\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string31 = /\/kerberos\-ldap\-password\-hunter/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string32 = /\/krb5\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string33 = /\/ldap\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string34 = /\/lookupsid\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string35 = /\/ntlm\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string36 = /\/ping6\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string37 = /\/smb\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string38 = /\/SMB_RPC\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string39 = /\/smb3\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string40 = /\/sniff\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string41 = /\/winregistry\.py.{0,1000}/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string42 = /\:9090.{0,1000}\/api\/v1\.0\/relays/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string43 = /\?convert_ccache_to_kirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string44 = /\?convert_kirbi_to_ccache/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string45 = /\\\$.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string46 = /\\\\127\.0\.0\.1\\c\$/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string47 = /\\impacket\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string48 = /\\krb5\\.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string49 = /\\ntlm\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string50 = /\\SMB_RPC\\.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string51 = /\\sniff\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string52 = /adcsattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string53 = /addcomputer\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string54 = /admin\.kirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string55 = /atexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string56 = /cat\s.{0,1000}\.ntds/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string57 = /changepasswd\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string58 = /cmd\.exe\s\/Q\s\/c\scd\s\\\s1\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__.{0,1000}\s2\>\&1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string59 = /dcomexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string60 = /dcsyncattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string61 = /dcsyncclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string62 = /dpapi\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string63 = /DumpNTLMInfo\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string64 = /examples\/netview\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string65 = /findDelegation\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string66 = /\-force\-forwardableet\-ADComputer/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string67 = /fortra\/impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string68 = /FrameManagementAssociationRequest\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string69 = /FrameManagementDeauthentication\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string70 = /FrameManagementProbeRequest\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string71 = /FrameManagementReassociationResponse\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string72 = /GetADUsers\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string73 = /Get\-GPPPassword\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string74 = /GetNPUsers\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string75 = /getPac\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string76 = /getTGT\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string77 = /GetUserSPNs\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string78 = /goldenPac\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string79 = /http\:\/\/127\.0\.0\.1\:9090\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string80 = /http\:\/\/localhost\:9090\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string81 = /httpattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string82 = /httpattacks\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string83 = /httprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string84 = /httprelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string85 = /imapattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string86 = /imaprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string87 = /impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library.
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string88 = /impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string89 = /impacket\-.{0,1000}\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string90 = /impacket\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string91 = /\'impacket\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string92 = /impacket\.git/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string93 = /impacket\.ldap/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string94 = /impacket\.ntlm/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string95 = /impacket\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string96 = /impacket\:latest/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string97 = /impacket__init__/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string98 = /impacket\-atexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string99 = /impacket\-dcomexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string100 = /impacket\-GetADUsers/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string101 = /impacket\-GetNPUsers/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string102 = /impacket\-getST/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string103 = /impacket\-getTGT/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string104 = /impacketldap_shell/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string105 = /impacketlogger/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string106 = /impacket\-lookupsid/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string107 = /impacketmssqlshell/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string108 = /impacket\-netview/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string109 = /impacketntlmrelayx/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string110 = /impacketos_ident/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string111 = /impacket\-psexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string112 = /impacket\-reg/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string113 = /impacket\-reg/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string114 = /impacketremcomsvc/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string115 = /impacketrpcdatabase/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string116 = /impacket\-rpcdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string117 = /impacket\-samrdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string118 = /impacketsecretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string119 = /impacket\-secretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string120 = /impacket\-secretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string121 = /impacketserviceinstall/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string122 = /impacket\-services/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string123 = /impacketsmbclient/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string124 = /impacket\-smbclient/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string125 = /impacket\-smbserver/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string126 = /impacket\-ticketer/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string127 = /impacketutils/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string128 = /impacket\-wmiexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string129 = /ImpactDecoder/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string130 = /ImpactPacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string131 = /import\simpacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string132 = /is_kirbi_file/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string133 = /karmaSMB\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string134 = /kerberos\-ldap\-password\-hunter\.sh/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string135 = /kerberosv5\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string136 = /keylistattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string137 = /kintercept\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string138 = /kintercept\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string139 = /krbrelayx/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string140 = /ldapasn1\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string141 = /ldapattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string142 = /LDAP\-Password\-Hunter/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string143 = /ldaprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string144 = /loadKirbiFile/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string145 = /lookupsid\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string146 = /mimikatz\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string147 = /mimilib\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string148 = /mqtt_check\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string149 = /mssqlattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string150 = /mssqlrelayclient\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string151 = /ndDelegation\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string152 = /netview\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string153 = /nmapAnswerMachine\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string154 = /ntfs\-read\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string155 = /ntlm\.py\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string156 = /ntlmrelayx\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string157 = /package\=impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string158 = /pcap_linktypes\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string159 = /pcapfile\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string160 = /psexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string161 = /raiseChild\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string162 = /rawrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string163 = /rbcd\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string164 = /rdp_check\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string165 = /registry\-read\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string166 = /relay.{0,1000}\/utils\/enum\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string167 = /rpcattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string168 = /rpcdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string169 = /rpcmap\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string170 = /rpcrelayclient\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string171 = /sambaPipe\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string172 = /samrdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string173 = /secretsdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string174 = /smbattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string175 = /smbexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string176 = /smbpasswd\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string177 = /smbrelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string178 = /smbrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string179 = /smbrelayx\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string180 = /smbserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string181 = /smtprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string182 = /sniffer\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string183 = /tcpshell\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string184 = /test_ccache_fromKirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string185 = /ticketConverter\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string186 = /ticketer\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string187 = /wcfrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string188 = /winregistry\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string189 = /wmipersist\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string190 = /Impacket\s/ nocase ascii wide

    condition:
        any of them
}

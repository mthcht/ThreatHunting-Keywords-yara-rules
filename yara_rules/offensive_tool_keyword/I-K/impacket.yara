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
        $string13 = /\sLMHASH:NTHASH/ nocase ascii wide
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
        $string42 = /:9090.{0,1000}\/api\/v1\.0\/relays/ nocase ascii wide
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
        $string58 = /dcomexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string59 = /dcsyncattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string60 = /dcsyncclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string61 = /dpapi\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string62 = /DumpNTLMInfo\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string63 = /examples\/netview\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string64 = /findDelegation\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string65 = /\-force\-forwardableet\-ADComputer/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string66 = /fortra\/impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string67 = /FrameManagementAssociationRequest\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string68 = /FrameManagementDeauthentication\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string69 = /FrameManagementProbeRequest\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string70 = /FrameManagementReassociationResponse\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string71 = /GetADUsers\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string72 = /Get\-GPPPassword\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string73 = /GetNPUsers\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string74 = /getPac\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string75 = /getTGT\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string76 = /GetUserSPNs\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string77 = /goldenPac\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string78 = /http:\/\/127\.0\.0\.1:9090\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string79 = /http:\/\/localhost:9090\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string80 = /httpattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string81 = /httpattacks\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string82 = /httprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string83 = /httprelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string84 = /imapattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string85 = /imaprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string86 = /impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library.
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string87 = /impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string88 = /impacket\-.{0,1000}\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string89 = /impacket\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string90 = /\'impacket\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string91 = /impacket\.git/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string92 = /impacket\.ldap/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string93 = /impacket\.ntlm/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string94 = /impacket\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string95 = /impacket:latest/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string96 = /impacket__init__/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string97 = /impacket\-atexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string98 = /impacket\-dcomexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string99 = /impacket\-GetADUsers/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string100 = /impacket\-GetNPUsers/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string101 = /impacket\-getST/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string102 = /impacket\-getTGT/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string103 = /impacketldap_shell/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string104 = /impacketlogger/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string105 = /impacket\-lookupsid/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string106 = /impacketmssqlshell/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string107 = /impacket\-netview/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string108 = /impacketntlmrelayx/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string109 = /impacketos_ident/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string110 = /impacket\-psexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string111 = /impacket\-reg/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string112 = /impacket\-reg/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string113 = /impacketremcomsvc/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string114 = /impacketrpcdatabase/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string115 = /impacket\-rpcdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string116 = /impacket\-samrdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string117 = /impacketsecretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string118 = /impacket\-secretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string119 = /impacket\-secretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string120 = /impacketserviceinstall/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string121 = /impacket\-services/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string122 = /impacketsmbclient/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string123 = /impacket\-smbclient/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string124 = /impacket\-smbserver/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string125 = /impacket\-ticketer/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string126 = /impacketutils/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string127 = /impacket\-wmiexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string128 = /ImpactDecoder/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string129 = /ImpactPacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string130 = /import\simpacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string131 = /is_kirbi_file/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string132 = /karmaSMB\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string133 = /kerberos\-ldap\-password\-hunter\.sh/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string134 = /kerberosv5\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string135 = /keylistattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string136 = /kintercept\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string137 = /kintercept\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string138 = /krbrelayx/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string139 = /ldapasn1\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string140 = /ldapattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string141 = /LDAP\-Password\-Hunter/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string142 = /ldaprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string143 = /loadKirbiFile/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string144 = /lookupsid\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string145 = /mimikatz\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string146 = /mimilib\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string147 = /mqtt_check\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string148 = /mssqlattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string149 = /mssqlrelayclient\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string150 = /ndDelegation\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string151 = /netview\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string152 = /nmapAnswerMachine\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string153 = /ntfs\-read\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string154 = /ntlm\.py\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string155 = /ntlmrelayx\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string156 = /package\=impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string157 = /pcap_linktypes\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string158 = /pcapfile\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string159 = /psexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string160 = /raiseChild\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string161 = /rawrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string162 = /rbcd\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string163 = /rdp_check\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string164 = /registry\-read\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string165 = /relay.{0,1000}\/utils\/enum\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string166 = /rpcattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string167 = /rpcdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string168 = /rpcmap\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string169 = /rpcrelayclient\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string170 = /sambaPipe\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string171 = /samrdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string172 = /secretsdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string173 = /smbattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string174 = /smbexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string175 = /smbpasswd\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string176 = /smbrelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string177 = /smbrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string178 = /smbrelayx\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string179 = /smbserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string180 = /smtprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string181 = /sniffer\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string182 = /tcpshell\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string183 = /test_ccache_fromKirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string184 = /ticketConverter\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string185 = /ticketer\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string186 = /wcfrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string187 = /winregistry\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string188 = /wmipersist\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string189 = /Impacket\s/ nocase ascii wide

    condition:
        any of them
}

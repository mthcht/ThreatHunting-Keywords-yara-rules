rule donpapi
{
    meta:
        description = "Detection patterns for the tool 'donpapi' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "donpapi"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string1 = /.{0,1000}\srun\sdonpapi.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string2 = /.{0,1000}\.py\s\s\-credz\s.{0,1000}\.txt\s.{0,1000}\s/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string3 = /.{0,1000}\/chrome_decrypt\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string4 = /.{0,1000}\/creddump7\/.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string5 = /.{0,1000}\/DonPAPI\.git.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string6 = /.{0,1000}\/DonPAPI\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string7 = /.{0,1000}\/firefox_decrypt\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string8 = /.{0,1000}\/lastpass\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string9 = /.{0,1000}\/login\-securite\/DonPAPI.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string10 = /.{0,1000}domcachedump\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string11 = /.{0,1000}donapapi\s\-pvk\s.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string12 = /.{0,1000}donpapi\s\-credz\s.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string13 = /.{0,1000}DonPAPI\.py\s.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string14 = /.{0,1000}donpapi\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string15 = /.{0,1000}dpapi_pick\/credhist\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string16 = /.{0,1000}dump_CREDENTIAL_MSOFFICE.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string17 = /.{0,1000}dump_CREDENTIAL_TASKSCHEDULER.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string18 = /.{0,1000}dump_CREDENTIAL_TSE.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string19 = /.{0,1000}dump_VAULT_INTERNET_EXPLORER.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string20 = /.{0,1000}dump_VAULT_NGC_LOCAL_ACCOOUNT.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string21 = /.{0,1000}dump_VAULT_WIN_BIO_KEY.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string22 = /.{0,1000}Get_DPAPI_Protected_Files.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string23 = /.{0,1000}GetChromeSecrets.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string24 = /.{0,1000}hashdump\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string25 = /.{0,1000}lsasecrets\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string26 = /.{0,1000}manager\/keepass\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string27 = /.{0,1000}manager\/mRemoteNG\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string28 = /.{0,1000}memorydump\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string29 = /.{0,1000}mRemoteNG\-local\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string30 = /.{0,1000}myseatbelt\.py.{0,1000}/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string31 = /.{0,1000}ppypykatz\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

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
        $string1 = /\srun\sdonpapi/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string2 = /\.py\s\s\-credz\s.{0,1000}\.txt\s.{0,1000}\s/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string3 = /\/chrome_decrypt\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string4 = /\/creddump7\// nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string5 = /\/DonPAPI\.git/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string6 = /\/DonPAPI\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string7 = /\/firefox_decrypt\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string8 = /\/lastpass\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string9 = /\/login\-securite\/DonPAPI/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string10 = /domcachedump\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string11 = /donapapi\s\-pvk\s/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string12 = /donpapi\s\-credz\s/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string13 = /DonPAPI\.py\s/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string14 = /donpapi\-master\.zip/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string15 = /dpapi_pick\/credhist\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string16 = /dump_CREDENTIAL_MSOFFICE/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string17 = /dump_CREDENTIAL_TASKSCHEDULER/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string18 = /dump_CREDENTIAL_TSE/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string19 = /dump_VAULT_INTERNET_EXPLORER/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string20 = /dump_VAULT_NGC_LOCAL_ACCOOUNT/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string21 = /dump_VAULT_WIN_BIO_KEY/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string22 = /Get_DPAPI_Protected_Files/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string23 = /GetChromeSecrets/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string24 = /hashdump\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string25 = /lsasecrets\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string26 = /manager\/keepass\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string27 = /manager\/mRemoteNG\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string28 = /memorydump\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string29 = /mRemoteNG\-local\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string30 = /myseatbelt\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string31 = /ppypykatz\.py/ nocase ascii wide

    condition:
        any of them
}

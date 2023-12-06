rule bofhound
{
    meta:
        description = "Detection patterns for the tool 'bofhound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bofhound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string1 = /\sBrc4LdapSentinelParser/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string2 = /\s\-\-brute\-ratel/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string3 = /\/beacon_202_no_acl\.log/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string4 = /\/beacon_257\-objects\.log/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string5 = /\/bloodhound_domain\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string6 = /\/bloodhound_domaintrust\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string7 = /\/bloodhound_gpo\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string8 = /\/bloodhound_object\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string9 = /\/bloodhound_ou\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string10 = /\/bloodhound_schema\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string11 = /\/bofhound\.git/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string12 = /\/ldap_search_bof\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string13 = /\/opt\/cobaltstrike\/logs/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string14 = /\\ldap_search_bof\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string15 = /badger_no_acl_1030_objects\.log/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string16 = /bofhound\s\-\-/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string17 = /bofhound\s\-i\s/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string18 = /bofhound\s\-o\s/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string19 = /bofhound\-main/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string20 = /brc4_ldap_sentinel\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string21 = /fortalice\/bofhound/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string22 = /from\sbofhound\simport\s/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string23 = /from\sbofhound\.ad\simport/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string24 = /import\sLdapSearchBofParser/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string25 = /pip3\sinstall\sbofhound/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string26 = /poetry\srun\sbofhound/ nocase ascii wide

    condition:
        any of them
}

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
        $string1 = /.{0,1000}\sBrc4LdapSentinelParser.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string2 = /.{0,1000}\s\-\-brute\-ratel.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string3 = /.{0,1000}\/beacon_202_no_acl\.log.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string4 = /.{0,1000}\/beacon_257\-objects\.log.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string5 = /.{0,1000}\/bloodhound_domain\.py.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string6 = /.{0,1000}\/bloodhound_domaintrust\.py.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string7 = /.{0,1000}\/bloodhound_gpo\.py.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string8 = /.{0,1000}\/bloodhound_object\.py.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string9 = /.{0,1000}\/bloodhound_ou\.py.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string10 = /.{0,1000}\/bloodhound_schema\.py.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string11 = /.{0,1000}\/bofhound\.git.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string12 = /.{0,1000}\/ldap_search_bof\.py.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string13 = /.{0,1000}\/opt\/cobaltstrike\/logs.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string14 = /.{0,1000}\\ldap_search_bof\.py.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string15 = /.{0,1000}badger_no_acl_1030_objects\.log.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string16 = /.{0,1000}bofhound\s\-\-.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string17 = /.{0,1000}bofhound\s\-i\s.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string18 = /.{0,1000}bofhound\s\-o\s.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string19 = /.{0,1000}bofhound\-main.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string20 = /.{0,1000}brc4_ldap_sentinel\.py.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string21 = /.{0,1000}fortalice\/bofhound.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string22 = /.{0,1000}from\sbofhound\simport\s.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string23 = /.{0,1000}from\sbofhound\.ad\simport.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string24 = /.{0,1000}import\sLdapSearchBofParser.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string25 = /.{0,1000}pip3\sinstall\sbofhound.{0,1000}/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string26 = /.{0,1000}poetry\srun\sbofhound.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

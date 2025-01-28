rule AADInternals
{
    meta:
        description = "Detection patterns for the tool 'AADInternals' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AADInternals"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string1 = " -ServiceName \"AADInternals\"" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string2 = /\/AADInternals\.git/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string3 = /\\AADInternals\\/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string4 = /\\CloudShell\.ps1/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string5 = /\\CloudShell_utils\.ps1/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string6 = /\\DCaaS_utils\.ps1/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string7 = /\\InjectDLL\.exe/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string8 = /\\PTASpy\.dll/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string9 = /\\PTASpy\.ps1/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string10 = /A\slittle\sservice\sto\ssteal\sthe\sAD\sFS\sDKM\ssecret\s\:\)/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string11 = /AADConnectProvisioningAgentWizard\.exe/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string12 = /AADInternals\.exe/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string13 = /AADInternals\.pdb/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string14 = /AADInternals\.psd1/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string15 = /AADInternals\.psm1/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string16 = "Add-AADIntAccessTokenToCache" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string17 = "Add-AADIntEASDevice" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string18 = "Add-AADIntRolloutPolicyGroups" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string19 = "Add-AADIntSPOSiteFiles" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string20 = "Add-AADIntSyncFabricServicePrincipal" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string21 = /AzureADConnectAuthenticationAgentService\.exe/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string22 = "ConvertTo-AADIntBackdoor" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string23 = "Disable-AADIntTenantMsolAccess" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string24 = /DSInternals\\DSInternals\.Replication\.dll/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string25 = /DSInternals\\DSInternals\.Replication\.Interop\.dll/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string26 = /DSInternals\\DSInternals\.Replication\.Model\.dll/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string27 = /DSInternals\\msvcp140\.dll/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string28 = /DSInternals\\NDceRpc\.Microsoft\.dll/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string29 = /DSInternals\\vcruntime140\.dll/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string30 = /DSInternals\\vcruntime140_1\.dll/ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string31 = "Enable-AADIntTenantMsolAccess" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string32 = "Export-AADIntADFSCertificates" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string33 = "Export-AADIntADFSConfiguration" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string34 = "Export-AADIntADFSEncryptionKey" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string35 = "Export-AADIntAzureCliTokens" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string36 = "Export-AADIntLocalDeviceCertificate" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string37 = "Export-AADIntLocalDeviceTransportKey" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string38 = "Export-AADIntProxyAgentBootstraps" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string39 = "Export-AADIntProxyAgentCertificates" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string40 = /Export\-AADIntProxyAgentCertificates\./ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string41 = "Export-AADIntSPOSiteFile" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string42 = "Export-AADIntTeamsTokens" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string43 = "Export-AADIntTokenBrokerTokens" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string44 = "Export-ADFSEncryptionKeyUsingService" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string45 = "Gerenios/AADInternals" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string46 = "Get-AADIntAADConnectStatus" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string47 = "Get-AADIntAccessAccessPackages" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string48 = "Get-AADIntAccessPackageAdmins" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string49 = "Get-AADIntAccessPackageCatalogs" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string50 = "Get-AADIntAccessPackages" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string51 = "Get-AADIntAccessToken" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string52 = "Get-AADIntAccessTokenFor<service>" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string53 = "Get-AADIntAccessTokenForAADGraph" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string54 = "Get-AADIntAccessTokenForAADIAMAPI" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string55 = "Get-AADIntAccessTokenForAADJoin" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string56 = "Get-AADIntAccessTokenForAccessPackages" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string57 = "Get-AADIntAccessTokenForAdmin" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string58 = "Get-AADIntAccessTokenForAzureCoreManagement" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string59 = "Get-AADIntAccessTokenForAzureMgmtAPI" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string60 = "Get-AADIntAccessTokenForCloudShell" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string61 = "Get-AADIntAccessTokenForEXO" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string62 = "Get-AADIntAccessTokenForEXOPS" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string63 = "Get-AADIntAccessTokenForIntuneMDM" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string64 = "Get-AADIntAccessTokenForMDM" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string65 = "Get-AADIntAccessTokenForMSCommerce" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string66 = "Get-AADIntAccessTokenForMSGraph" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string67 = "Get-AADIntAccessTokenForMSPartner" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string68 = "Get-AADIntAccessTokenForMySignins" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string69 = "Get-AADIntAccessTokenForOfficeApps" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string70 = "Get-AADIntAccessTokenForOneDrive" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string71 = "Get-AADIntAccessTokenForOneNote" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string72 = "Get-AADIntAccessTokenForOneOfficeApps" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string73 = "Get-AADIntAccessTokenForPTA" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string74 = "Get-AADIntAccessTokenForSARA" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string75 = "Get-AADIntAccessTokenForSPO" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string76 = "Get-AADIntAccessTokenForTeams" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string77 = "Get-AADIntAccessTokenForWHfB" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string78 = "Get-AADIntAccessTokenUsingAdminAPI" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string79 = "Get-AADIntAccessTokenUsingIMDS" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string80 = "Get-AADIntAccessTokenWithRefreshToken" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string81 = "Get-AADIntAccountSkus" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string82 = "Get-AADIntADFSPolicyStoreRules" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string83 = "Get-AADIntAdminPortalAccessTokenUsingCBA" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string84 = "Get-AADIntADUserNTHash" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string85 = "Get-AADIntAdUserNTHash" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string86 = "Get-AADIntADUserThumbnailPhoto" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string87 = "Get-AADIntAgentProxyGroups" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string88 = "Get-AADIntAzureADFeature" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string89 = "Get-AADIntAzureADFeatures" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string90 = "Get-AADIntAzureADPolicies" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string91 = "Get-AADIntAzureAuditLog" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string92 = "Get-AADIntAzureClassicAdministrators" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string93 = "Get-AADIntAzureDiagnosticSettings" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string94 = "Get-AADIntAzureDirectoryActivityLog" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string95 = "Get-AADIntAzureInformation" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string96 = "Get-AADIntAzureResourceGroups" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string97 = "Get-AADIntAzureRoleAssignmentId" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string98 = "Get-AADIntAzureSignInLog" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string99 = "Get-AADIntAzureSubscriptions" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string100 = "Get-AADIntAzureTenants" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string101 = "Get-AADIntAzureVMRdpSettings" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string102 = "Get-AADIntAzureVMs" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string103 = "Get-AADIntAzureWireServerAddress" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string104 = "Get-AADIntB2CEncryptionKeys" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string105 = "Get-AADIntCache" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string106 = "Get-AADIntCertificate" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string107 = "Get-AADIntCompanyInformation" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string108 = /Get\-AADIntCompanyInformation\./ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string109 = "Get-AADIntCompanyTags" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string110 = "Get-AADIntComplianceAPICookies" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string111 = "Get-AADIntConditionalAccessPolicies" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string112 = "Get-AADIntDesktopSSOAccountPassword" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string113 = "Get-AADIntDeviceCompliance" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string114 = "Get-AADIntDeviceRegAuthMethods" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string115 = "Get-AADIntDevices" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string116 = "Get-AADIntDeviceTransportKey" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string117 = "Get-AADIntDiagnosticSettingsDetails" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string118 = "Get-AADIntDPAPIKeys" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string119 = "Get-AADIntEASAutoDiscover" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string120 = "Get-AADIntEASAutoDiscoverV1" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string121 = "Get-AADIntEASOptions" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string122 = "Get-AADIntEndpointInstances" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string123 = "Get-AADIntEndpointIps" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string124 = "Get-AADIntError" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string125 = "Get-AADIntFOCIClientIDs" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string126 = "Get-AADIntGlobalAdmins" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string127 = "Get-AADIntHybridHealthServiceAccessToken" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string128 = "Get-AADIntHybridHealthServiceAgentInfo" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string129 = "Get-AADIntHybridHealthServiceBlobUploadKey" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string130 = "Get-AADIntHybridHealthServiceEventHubPublisherKey" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string131 = "Get-AADIntHybridHealthServiceMemberCredentials" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string132 = "Get-AADIntHybridHealthServiceMembers" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string133 = "Get-AADIntHybridHealthServiceMonitoringPolicies" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string134 = "Get-AADIntHybridHealthServices" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string135 = "Get-AADIntIdentityTokenByLiveId" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string136 = "Get-AADIntImmutableID" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string137 = "Get-AADIntKerberosDomainSyncConfig" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string138 = "Get-AADIntKerberosTicket" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string139 = "Get-AADIntLocalDeviceJoinInfo" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string140 = "Get-AADIntLocalUserCredentials" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string141 = "Get-AADIntLoginInformation" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string142 = "Get-AADIntLSABackupKeys" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string143 = "Get-AADIntLSASecrets" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string144 = "Get-AADIntMobileDevices" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string145 = "Get-AADIntMSPartnerContracts" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string146 = "Get-AADIntMSPartnerOffers" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string147 = "Get-AADIntMSPartnerOrganizations" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string148 = "Get-AADIntMSPartnerPublishers" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string149 = "Get-AADIntMSPartnerRoleMembers" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string150 = "Get-AADIntMSPartners" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string151 = "Get-AADIntMyTeams" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string152 = "Get-AADIntOAuthGrants" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string153 = "Get-AADIntODAuthenticationCookie" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string154 = "Get-AADIntOfficeUpdateBranch" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string155 = "Get-AADIntOneDriveFiles" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string156 = "Get-AADIntOpenIDConfiguration" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string157 = "Get-AADIntPortalAccessTokenUsingCBA" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string158 = "Get-AADIntProxyAgents" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string159 = "Get-AADIntProxyGroups" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string160 = "Get-AADIntReadAccessTokenForAADGraph" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string161 = "Get-AADIntRecentLocations" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string162 = "Get-AADIntRolloutPolicies" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string163 = "Get-AADIntRolloutPolicyGroups" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string164 = "Get-AADIntSARAUserInfo" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string165 = "Get-AADIntSeamlessSSO" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string166 = "Get-AADIntSelfServicePurchaseProducts" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string167 = "Get-AADIntServiceLocations" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string168 = "Get-AADIntServicePrincipals" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string169 = "Get-AADIntSettings" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string170 = "Get-AADIntSharedWithUser" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string171 = "Get-AADIntSkypeToken" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string172 = "Get-AADIntSPOAuthenticationHeader" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string173 = "Get-AADIntSPOIDCRL" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string174 = "Get-AADIntSPOServiceInformation" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string175 = "Get-AADIntSPOSettings" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string176 = "Get-AADIntSPOSiteGroups" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string177 = "Get-AADIntSPOSiteUsers" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string178 = "Get-AADIntSPOUserProperties" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string179 = "Get-AADIntSubscriptions" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string180 = "Get-AADIntSyncConfiguration" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string181 = "Get-AADIntSyncCredentials" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string182 = "Get-AADIntSyncDeviceConfiguration" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string183 = "Get-AADIntSyncEncryptionKey" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string184 = "Get-AADIntSyncEncryptionKeyInfo" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string185 = "Get-AADIntSyncFeatures" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string186 = "Get-AADIntSyncObjects" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string187 = "Get-AADIntSystemMasterkeys" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string188 = "Get-AADIntTeamsAvailability" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string189 = "Get-AADIntTeamsMessages" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string190 = "Get-AADIntTenantApplications" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string191 = "Get-AADIntTenantAuthenticationMethods" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string192 = "Get-AADIntTenantAuthPolicy" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string193 = "Get-AADIntTenantDetails" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string194 = "Get-AADIntTenantDomain" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string195 = "Get-AADIntTenantDomains" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string196 = "Get-AADIntTenantGuestAccess" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string197 = "Get-AADIntTenantID" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string198 = "Get-AADIntTenantOrganisationInformation" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string199 = "Get-AADIntTranslation" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string200 = "Get-AADIntUnifiedAuditLogSettings" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string201 = "Get-AADIntUserConnections" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string202 = "Get-AADIntUserDetails" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string203 = "Get-AADIntUserMasterkeys" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string204 = "Get-AADIntUserMFA" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string205 = "Get-AADIntUserMFAApps" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string206 = "Get-AADIntUserNTHash" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string207 = "Get-AADIntUserPRTKeys" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string208 = "Get-AADIntUserPRTToken" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string209 = "Get-AADIntUserRealm" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string210 = "Get-AADIntUserRealmExtended" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string211 = "Get-AADIntUserRealmV2" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string212 = "Get-AADIntUserRealmV3" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string213 = "Get-AADIntWindowsCredentialsSyncConfig" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string214 = "Get-Module AADInternals" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string215 = "Grant-AADIntAzureUserAccessAdminRole" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string216 = /https\:\/\/aadinternals\.com\/aadinternals\// nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string217 = "Import-Module AADInternals" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string218 = "Install-AADIntForceNTHash" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string219 = "Install-Module AADInternals" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string220 = "Install-Module AADInternals" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string221 = "Invoke-AADIntAzureVMScript" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string222 = "Invoke-AADIntPhishing" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string223 = "Invoke-AADIntReconAsGuest" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string224 = "Invoke-AADIntReconAsInsider" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string225 = "Invoke-AADIntReconAsOutsider" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string226 = "Invoke-AADIntSyncAgent" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string227 = "Invoke-AADIntUserEnumerationAsGuest" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string228 = "Invoke-AADIntUserEnumerationAsInsider" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string229 = "Invoke-AADIntUserEnumerationAsOutsider" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string230 = "Join-AADIntAzureAD" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string231 = "Join-AADIntDeviceToAzureAD" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string232 = /Join\-AADIntDeviceToAzureAD\./ nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string233 = "Join-AADIntDeviceToIntune" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string234 = "Join-AADIntLocalDeviceToAzureAD" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string235 = "Join-AADIntOnPremDeviceToAzureAD" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string236 = "New-AADIntADFSRefreshToken" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string237 = "New-AADIntADFSSelfSignedCertificates" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string238 = "New-AADIntB2CAuthorizationCode" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string239 = "New-AADIntB2CRefreshToken" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string240 = "New-AADIntBackdoor" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string241 = "New-AADIntBulkPRTToken" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string242 = "New-AADIntCertificate" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string243 = "New-AADIntGuestInvitation" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string244 = "New-AADIntHybridHealthService" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string245 = "New-AADIntHybridHealthServiceMember" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string246 = "New-AADIntHybridHealtServiceEvent" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string247 = "New-AADIntInvitationVBA" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string248 = "New-AADIntMOERADomain" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string249 = "New-AADIntMSPartnerDelegatedAdminRequest" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string250 = "New-AADIntOneDriveSettings" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string251 = "New-AADIntOTP" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string252 = "New-AADIntOTPSecret" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string253 = "New-AADIntP2PDeviceCertificate" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string254 = "New-AADIntSAML2Token" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string255 = "New-AADIntSAMLToken" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string256 = "New-AADIntUserPRTToken" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string257 = "Open-AADIntOffice365Portal" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string258 = "Open-AADIntOWA" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string259 = "Read-AADIntAccesstoken" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string260 = "Read-AADIntConfiguration" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string261 = "Register-AADIntHybridHealthServiceAgent" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string262 = "Register-AADIntMFAApp" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string263 = "Register-AADIntProxyAgent" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string264 = "Register-AADIntPTAAgent" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string265 = "Register-AADIntSyncAgent" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string266 = "Remove-AADIntAccessDeviceFromIntune" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string267 = "Remove-AADIntAzureDiagnosticSettings" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string268 = "Remove-AADIntDeviceFromAzureAD" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string269 = "Remove-AADIntForceNTHash" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string270 = "Remove-AADIntHybridHealthService" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string271 = "Remove-AADIntHybridHealthServiceMember" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string272 = "Remove-AADIntMSPartnerDelegatedAdminRoles" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string273 = "Remove-AADIntPTASpy" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string274 = "Remove-AADIntRolloutPolicy" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string275 = "Remove-AADIntRolloutPolicyGroups" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string276 = "Remove-AADIntTeamsMessages" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string277 = "Restore-AADIntADFSAutoRollover" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string278 = "Search-AADIntTeamsUser" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string279 = "Search-AADIntUnifiedAuditLog" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string280 = "Send-AADIntEASMessage" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string281 = "Send-AADIntHybridHealthServiceEventBlob" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string282 = "Send-AADIntHybridHealthServiceEvents" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string283 = "Send-AADIntOneDriveFile" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string284 = "Send-AADIntOutlookMessage" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string285 = "Send-AADIntTeamsMessage" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string286 = "Set-AADIntADFSConfiguration" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string287 = "Set-AADIntADFSPolicyStoreRules" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string288 = "Set-AADIntADSyncAccountPassword" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string289 = "Set-AADIntADSyncEnabled" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string290 = "Set-AADIntAzureADFeature" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string291 = "Set-AADIntAzureADPolicyDetail" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string292 = "Set-AADIntAzureRoleAssignment" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string293 = "Set-AADIntDesktopSSO" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string294 = "Set-AADIntDesktopSSOEnabled" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string295 = "Set-AADIntDeviceCompliant" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string296 = "Set-AADIntDeviceRegAuthMethods" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string297 = "Set-AADIntDeviceTransportKey" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string298 = "Set-AADIntDeviceWHfBKey" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string299 = "Set-AADIntDiagnosticSettingsDetails" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string300 = "Set-AADIntEASSettings" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string301 = "Set-AADIntOfficeUpdateBranch" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string302 = "Set-AADIntPassThroughAuthentication" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string303 = "Set-AADIntPasswordHashSyncEnabled" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string304 = "Set-AADIntProxySettings" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string305 = "Set-AADIntPTACertificate" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string306 = "Set-AADIntRolloutPolicy" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string307 = "Set-AADIntSelfServicePurchaseProduct" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string308 = "Set-AADIntSetting" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string309 = "Set-AADIntSPOSiteMembers" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string310 = "Set-AADIntSPOUserProperty" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string311 = "Set-AADIntSyncFeature" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string312 = "Set-AADIntSyncFeatures" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string313 = "Set-AADIntTeamsAvailability" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string314 = "Set-AADIntTeamsMessageEmotion" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string315 = "Set-AADIntTeamsStatusMessage" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string316 = "Set-AADIntTenantGuestAccess" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string317 = "Set-AADIntUnifiedAuditLogSettings" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string318 = "Set-AADIntUserAgent" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string319 = "Set-AADIntUserMFA" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string320 = "Set-AADIntUserMFAApps" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string321 = "Set-AADIntUserPassword" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string322 = "Start-AADIntCloudShell" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string323 = "Start-AADIntDeviceIntuneCallback" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string324 = "Start-AADIntSpeech" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string325 = "Update-AADIntADFSFederationSettings!\"" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string326 = "Update-AADIntADFSFederationSettings" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string327 = "Update-AADIntSPOSiteFile" nocase ascii wide
        // Description: AADInternals PowerShell module for administering Azure AD and Office 365
        // Reference: https://github.com/Gerenios/AADInternals
        $string328 = "Update-AADIntSyncCredentials" nocase ascii wide

    condition:
        any of them
}

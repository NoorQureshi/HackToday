# PowerUp

PowerUp.ps1 Invoke-AllChecks

```text
powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Invoke-AllChecks}"
```

**Checklists**

* [x] Current privileges
* [x] Unquoted service paths
* [x] Service executable permissions
* [x] Service permissions
* [x] %PATH% for hijackable DLL locations
* [x] AlwaysInstallElevated registry key
* [x] Autologon credentials in registry
* [x] Modifidable registry autoruns and configs
* [x] Modifiable schtask files/configs
* [x] Unattended install files
* [x] Encrypted web.config strings
* [x] Encrypted application pool and virtual directory passwords
* [x] Plaintext passwords in McAfee SiteList.xml
* [x] Cached Group Policy Preferences .xml files


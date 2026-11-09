# AD-Schnellcheck – kostenloser Active-Directory-Check mit PowerShell

PowerShell-Skript, das ein Active Directory in **8 Punkten** auf typische Schwachstellen prüft und einen übersichtlichen **HTML-Bericht auf Deutsch** erzeugt. Es arbeitet **ausschließlich lesend**: Es ändert nichts im Verzeichnis, legt nichts an und überträgt keine Daten.

![Beispielbericht](Beispielbericht.png)

## Was geprüft wird

| Nr. | Prüfpunkt |
|---|---|
| R1 | Schwache Einstellungen in der Domänen-Kennwortrichtlinie (Länge, Komplexität, Chronik, Kontosperrung) |
| A1 | Zu viele privilegierte Konten (auch über verschachtelte Gruppen) |
| A4 | Administratorkonten, deren Kennwort nie abläuft |
| K1 | Benutzerkonten, deren Kennwort nie abläuft |
| K2 | Konten, die kein Kennwort brauchen (PASSWD_NOTREQD) |
| K4 | Kerberos-Vorauthentifizierung abgeschaltet (AS-REP-Roasting) |
| K10 | Gastkonto aktiviert |
| C1 | Computer mit nicht mehr unterstütztem Windows (bis Windows 10, Server 2012 R2) |

Jeder Befund kommt mit Erklärung und Empfehlung; auf Wunsch zusätzlich als CSV für Excel.

## Start

```powershell
powershell -ExecutionPolicy Bypass -File .\AD-Schnellcheck.ps1
```

Optionen: `-Csv` (CSV je Befund), `-Ausgabe C:\Berichte\ad.html`, `-MaxAdmins 5`, `-Server <DC>`, `-Anmeldung (Get-Credential)` (z. B. von einem Rechner außerhalb der Domäne), `-NichtOeffnen`, `-PassThru`.

**Voraussetzungen:** Windows PowerShell 5.1, PowerShell-Modul `ActiveDirectory` (auf Domänencontrollern vorhanden, sonst RSAT), ein normales Domänenkonto mit Leserechten. Administratorrechte sind nicht nötig.

Getestet mit Windows Server 2019, 2022 und 2025 in Testdomänen (deutsches Windows).

## Die Abfragen auch von Hand

Wer das Skript nicht ausführen will, kann die Kernprüfungen einzeln abfragen. Alle nur lesend und sprachunabhängig (feste Kennungen statt Gruppennamen), getestet unter Windows Server 2025 (deutsch).

```powershell
$sid = (Get-ADDomain).DomainSID.Value
# Kennwortrichtlinie
Get-ADDefaultDomainPasswordPolicy | Select MinPasswordLength, ComplexityEnabled, PasswordHistoryCount, LockoutThreshold
# Domänen-Admins (RID 512), verschachtelt aufgelöst
Get-ADGroupMember "$sid-512" -Recursive | Select SamAccountName, objectClass
# Admins mit Kennwort, das nie abläuft
Get-ADGroupMember "$sid-512" -Recursive | Get-ADUser -Properties PasswordNeverExpires | Where PasswordNeverExpires | Select SamAccountName
# Benutzer, deren Kennwort nie abläuft
Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' | Select SamAccountName
# Konten ohne Kennwortpflicht
Get-ADUser -Filter 'PasswordNotRequired -eq $true -and Enabled -eq $true' | Select SamAccountName
# Kerberos-Vorauthentifizierung aus (AS-REP-Roasting)
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | Select SamAccountName
# Gastkonto (RID 501)
Get-ADUser "$sid-501" -Properties Enabled | Select SamAccountName, Enabled
# Veraltete Windows-Versionen (LTSC ausgenommen)
Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem |
  Where { $_.OperatingSystem -match 'Windows (7|8|10|XP|Vista)|Server 2008|Server 2012' -and $_.OperatingSystem -notmatch 'LTSC|LTSB' } |
  Select Name, OperatingSystem
```

## Vollversion

Der Schnellcheck ist eine Kurzfassung des **AD-Prüfberichts** (21 Prüfpunkte, Anleitung als PDF). Zusätzlich geprüft werden dort u. a. Dienstkonten mit Administratorrechten, Konten mit SPN (Kerberoasting), mögliche Kennwörter im Beschreibungsfeld, deaktivierte Admin-Konten, verschachtelte Admin-Gruppen, inaktive Benutzer- und Computerkonten, das Alter des krbtgt-Kennworts, leere Gruppen und der AD-Papierkorb.

Weitere Prüfskripte (alle nur lesend, mit HTML-Bericht): Domänencontroller-Gesundheit, DNS/DHCP, Rechner-Inventar mit Support-Ende, Kerberos-Altlasten, Berechtigungen, Gruppenrichtlinien, Anmelde- und Sperrbericht, Dateiserver.

➜ **[AD-Prüfbericht (Vollversion) auf Gumroad](https://mueller86.gumroad.com/l/fcneoc)** · **[alle Skripte auf Gumroad](https://mueller86.gumroad.com)** · **[IT Admin Tools by MM auf Etsy](https://www.etsy.com/shop/ITAdminToolsbyMM)**

## Hinweise

- Der Bericht enthält Konto- und Rechnernamen – bitte vertraulich behandeln.
- Der Bericht zeigt Auffälligkeiten anhand fester Regeln. Er ersetzt keine Sicherheitsprüfung und erhebt keinen Anspruch auf Vollständigkeit.
- Nutzung auf eigene Verantwortung, siehe [LICENSE](LICENSE).
- Bei der Ausarbeitung wurden KI-Werkzeuge unterstützend eingesetzt; Inhalte und Skript wurden fachlich geprüft und im Testlab getestet.

---

### English

Free, read-only PowerShell script that checks an Active Directory domain for 8 common weaknesses and writes an HTML report (report language: German).

Checks: domain password policy (length, complexity, history, lockout), too many privileged accounts (nested groups resolved), admin accounts with non-expiring passwords, user accounts with non-expiring passwords, accounts that do not require a password (PASSWD_NOTREQD), Kerberos pre-authentication disabled (AS-REP roasting), enabled guest account, computers running unsupported Windows versions.

- No changes to the directory, no data leaves the machine.
- Requires Windows PowerShell 5.1 and the ActiveDirectory module (RSAT); a normal domain user is enough.
- Tested on Windows Server 2019, 2022 and 2025 (German) in lab domains.
- Run: `powershell -ExecutionPolicy Bypass -File .\AD-Schnellcheck.ps1`
- Full version with 21 checks: https://mueller86.gumroad.com/l/fcneoc

#New-SelfSignedCertificate -Type Custom -Subject "E=john.lan@bmo.com,CN=John Lan" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.4","2.5.29.17={text}email=john.lan@bmo.com&upn=john.lan@bmo.com") -KeyAlgorithm RSA -KeyLength 2048 -SmimeCapabilities -CertStoreLocation "Cert:\CurrentUser\My"

#
# step 1:   create a certificate, make private key exportable, non-protected
#           copy and save cert thumprint, which will be used in step 4 script
# New-SelfSignedCertificate  -Subject "E=john.lan@bmo.com,CN=John Lan"  -CertStoreLocation "Cert:\CurrentUser\My"  -KeyExportPolicy Exportable  -Provider "Microsoft RSA SChannel Cryptographic Provider"


#
# Step 2:   export certificate to a file (without private key) / in OS. Give the cert file to client
#   this cert file will be used in step 3 script, which will be run by client to encrypt file
# 

#region Functions
# below 2 functions are credit of http://jeffmurr.com/blog/?p=228
# with quite substantial revision:
#       - statements that generate cert from cert file are moved from within function to caller
#       - statements that gets cert from thumbprint are moved from within function to caller
#       - no longer using string as input to encrypt function; no longer using string as output from decrypt function. Both use byte[] now
#       - accordingly, caller must read clear text file as byte[]; caller must write decrypted text as byte[]
<#
Function Encrypt-Asymmetric {
[CmdletBinding()]
[OutputType([System.String])]
param(
    [Parameter(Position=0, Mandatory=$true)][AllowEmptyString()][System.String]
    $ClearText,
    [Parameter(Position=1, Mandatory=$true)][ValidateNotNullOrEmpty()][ValidateScript({Test-Path $_ -PathType Leaf})][System.String]
    $PublicCertFilePath
)
    # Encrypts a string with a public key
    $PublicCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PublicCertFilePath)
    $ByteArray = [System.Text.Encoding]::UTF8.GetBytes($ClearText)
    try{$EncryptedByteArray = $PublicCert.PublicKey.Key.Encrypt($ByteArray,$true)}
    catch{throw "exception from Encrypt-Asymmetric: `r`n $_.categoaryInfo"}
    $EncryptedBase64String = [Convert]::ToBase64String($EncryptedByteArray)

    Return $EncryptedBase64String 
}
#>
Function Encrypt-Asymmetric { #override function. Use byte array and certObj as input directly
[CmdletBinding()]
[OutputType([System.String])]
param(
    [Parameter(Position=0, Mandatory=$true)][ValidateNotNullOrEmpty()][byte[]]
    $ByteArray,
    [Parameter(Position=1, Mandatory=$true)][ValidateNotNullOrEmpty()][System.Security.Cryptography.X509Certificates.X509Certificate2]
    $PublicCert
)
    # Encrypts a string with a public key
    # try{$EncryptedByteArray = $PublicCert.PublicKey.Key.Encrypt($ByteArray,$true)} #this overload works only in PS5
    try{$EncryptedByteArray = $PublicCert.PublicKey.Key.Encrypt($ByteArray,[System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)} # overload works in PS7
        catch{throw "exception from Encrypt-Asymmetric: `r`n $(_.categoaryInfo)"}
    $EncryptedBase64String = [Convert]::ToBase64String($EncryptedByteArray)

    Return $EncryptedBase64String 
}

Function Decrypt-Asymmetric
{
[CmdletBinding()]
[OutputType([System.String])]
param(
    [Parameter(Position=0, Mandatory=$true)][ValidateNotNullOrEmpty()][System.String]
    $EncryptedBase64String,
    [Parameter(Position=1, Mandatory=$true)][ValidateNotNullOrEmpty()][System.Security.Cryptography.X509Certificates.X509Certificate2]
    $Cert
)
    # Decrypts text using the private key
    # Assumes the certificate is in the LocalMachine\My (Personal) Store
    #$Cert = Get-ChildItem cert:\CurrentUser\My | where { $_.Thumbprint -eq $CertThumbprint }
    if($Cert) {
        $EncryptedByteArray = [Convert]::FromBase64String($EncryptedBase64String)
        # below version of decrypt overload no longer exists in PS 7. This works only PS5
        # $ClearText = [System.Text.Encoding]::UTF8.GetString($Cert.PrivateKey.Decrypt($EncryptedByteArray,$true))
        #
        #$ClearText = [System.Text.Encoding]::UTF8.GetString($Cert.PrivateKey.Decrypt($EncryptedByteArray,[System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))
        [byte[]]$ClearText = ($Cert.PrivateKey.Decrypt($EncryptedByteArray,[System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))
        #returns a byte[] directly rather than a string
    }
    Else {Write-Error "Please provide a valid certificate!"}

    Return $ClearText
}
#endregion Functions

#
# Step 3: Give the certificate to the other party where they can use it to encrypt text using "Encrypt-Asymmetric" function below
#          Encrypt-asymmetric -clearText "clearText" -PublicCertFilePath "Full absolute path and file name to cert"
#       encrypt function can only encrypt limited size each time, so we have to break cleartext file into smaller chunks
# 

write-host "-----------------------------"
write-host " Encrypting ..."
write-host "-----------------------------"
try{new-item "encrypted.txt" -Force -Confirm:$false > $null}
catch {}
$count=0

#region using chunk'ed string as input
<# using chunk'ed string as input
$originaltxt=(get-content .\original.html) -join "`r`n"
$arrString=$originaltxt -split '(.{60})'  # break file into smaller chunks. CSP can only enncrypt 128 bytes at a time
foreach($line in $arrString){
    #write-host "---[$line]---"
    $count+=1
    if ($count%59 -eq 0) {write-host "."}
    else {write-host "." -NoNewline}
    try{Encrypt-Asymmetric -ClearText $line -PublicCertPath $PublicCertPath  -ErrorAction Stop | add-Content "encrypted.txt"}
    catch{
        write-host "---[$line]---" -ForegroundColor Red
        write-host "line number $count" -ForegroundColor Yellow
        write-host $_.categoryinfo
    }
}
#>
#endregion

#region using byte array and certObj directly as input
# using chunk'ed string as input
#$byteArr = [System.IO.File]::ReadAllBytes("c:\temp\original.html") #PS v5
$byteArr = Get-Content "./original.html" -asByteStream -raw  #PS v6 above
$PublicCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\temp\selfSignedCert.cer")
$count =0
for($i=0;($i -lt ([int][math]::ceiling($byteArr.Count/60))); $i++){
    #write-host "---[$line]---"
    $chunk=$byteArr[($i*60)..(($i+1)*60-1)]
    $count +=1
    if ($count%59 -eq 0) {write-host "."}
    else {write-host "." -NoNewline}
    try{Encrypt-Asymmetric -byteArray $chunk -PublicCert $PublicCert  -ErrorAction Stop | add-Content "encrypted.txt"}
    catch{
        #write-host "---[$line]---" -ForegroundColor Red
        write-host "line number $count" -ForegroundColor Yellow
        write-host $_.categoryinfo
    }
}
#

#endregion using byte array and certObj directly as input


#region decrypting
#
# Step 4: Decrypt file as below
# 
#
$encyptedTxt = Get-Content "encrypted.txt"
write-host "`r`n-----------------------------"
write-host " Decrypting ..."
write-host "-----------------------------"
$cleartxt =[byte[]]@()
$certThumbprint= "FB70294DB58D82ACF92470F20B77306D5AE0F48D"
$Cert = Get-ChildItem cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $CertThumbprint }
    $count=0
foreach ($line in $encyptedTxt){
    $count++
    if ($count%59 -eq 0) {write-host "."}
    else {write-host "." -NoNewline}

    #$cleartxt+= [System.Text.Encoding]::utf8.(Decrypt-Asymmetric -EncryptedBase64String $line -Cert $cert)
    $cleartxt +=  (Decrypt-Asymmetric -EncryptedBase64String $line -Cert $cert)
}
#$cleartxt | Set-Content "./decrypted.txt" -encoding UTF8 -Force -Confirm:$false 
#$cleartxt | Set-Content "./decrypted.txt" -asByteStream  -Force -Confirm:$false 
[System.IO.File]::WriteAllBytes("c:\temp\decrypted.txt", $cleartxt)

#
#endregion decrypting
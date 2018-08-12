Import-Module ActiveDirectory
$pass = ([char[]]([char]33..[char]95) + ([char[]]([char]97..[char]126)) + 0..9 | sort {Get-Random})[0..8] -join ''
$Fname = Read-Host -Prompt "Enter First Name"
$Lname = Read-Host -Prompt "Enter Last Name"
$email = Read-Host -Prompt "Enter Current Email"
$user = ($Fname + "." + $Lname)
$spass = ConvertTo-SecureString $pass -AsPlainText -Force
$oupath = "OU=Users,OU=home,DC=home,DC=com"
New-ADUser -AccountPassword $spass -ChangePasswordAtLogon $True -DisplayName $user -Enabled $True -SamAccountName $user -Name "$Fname $Lname" -GivenName $Fname -Surname $Lname -Path $oupath -UserPrincipalName "$Fname.$Lname" 
echo "The user $user has been created"
$From = "Support@domain.com"
$subject = "Login Password"
$body = "Username: $user Password: $pass"
$SMTPServer = "smtp.domain.com"
$SMTPPort = "465"
Send-MailMessage -From $From -to $email -Subject $Subject -Body $Body -SmtpServer $SMTPServer -port $SMTPPort -UseSsl -Credential (Get-Credential)
echo "$user has been emailed at $email login"
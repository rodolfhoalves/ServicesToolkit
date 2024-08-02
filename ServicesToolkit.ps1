# ===========================================
#    Power System Center - SERVICES TOOLKIT
#    Maintainer: Rodolfho Queiroz
#    Email:  rodolfho.queiroz@subnet.com 
#
#    Maintainer: 
#    Email:   
# ===========================================

# testing

# Function to display menu and get user choice
function Show-Menu {
    Clear-Host

    Write-Host "=========================================================================================" -ForegroundColor Cyan
    Write-Host "                          Power System Center - SERVICES TOOLKIT                         " -ForegroundColor Yellow
    Write-Host "                                      v:0.1 beta                                         " -ForegroundColor Yellow
    Write-Host "=========================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " 1. Test SQL Server Connection String"
    Write-Host " 2. Test Socket Connectivity (client)"
    Write-Host " 3. Test PSC requirements (DCS)"
    Write-Host " 4. Test PSC Requirements (CAS)"
    Write-Host " 5. SHA1 Hash Generator"
    Write-Host " 6. SHA256 Hash Generator"
    Write-Host " 7. Show OS details"
    Write-Host " 0. Quit"
    Write-Host ""
    Write-Host "=========================================================================================" -ForegroundColor Cyan
    $choice = Read-Host "Choose an option"
    return $choice
}


# Function for Option 1
function Option-1 {
    Write-Host "Insert SQL Server Connection to be tested:"
    Write-Host "e.g: server=servename\PSC;Database=subnet.psc;Integrated Security=True"
    $connection_String = Read-Host "Insert here"

        Write-Host "Connecting with the user: $(whoami)" -ForegroundColor Yellow
        try {$connection = New-Object System.Data.SqlClient.SqlConnection
            $connection.ConnectionString = $connection_String
            $connection.Open()
            Write-Host "CONNECTION SUCCESSFUL!!" -ForegroundColor Green
            Write-Output ""
   

            # Create an SQL command to execute the query
            $command = $connection.CreateCommand()
            $command.CommandText = "select @@version"
            # Execute the command and read the results
            $reader = $command.ExecuteReader()
            # Process the results and print them
            while ($reader.Read()) {
                # Creates a formatted result line
                $row = ""
                for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                    $row += $reader.GetName($i) + ": " + $reader.GetValue($i) + "  "
                }
                Write-Output $row
            }

            # Closes the reader and connection
            $reader.Close()



            # Create an SQL command to execute the query
            $command = $connection.CreateCommand()
            $command.CommandText = "SELECT name FROM sys.databases"

            # Execute the command and read the results
            $reader = $command.ExecuteReader()

            # Process the results and print them
            Write-Host "Databases in this instance:" -ForegroundColor Cyan
            while ($reader.Read()) {
                # Process the results and print them
                Write-Output $reader["name"]
            }
            $reader.Close()

            $connection.Close()
        } catch {
            Write-Output "Connection failed: $_"
        }


    Write-Output ""
    Pause
}

# Function for Option 2
function Option-2 {

    function TestConnection {    

        do {
            # Requests the user's IP
            $ip = Read-Host "Enter IP/Hostname for connectivity test"

            # Prompts for user port
            $porta = Read-Host "Enter the TCP port for connectivity testing"

            # Test connectivity
            $result = Test-NetConnection -ComputerName $ip -Port $porta

            # Display the result
            if ($result.TcpTestSucceeded) {
                Write-Host "Successful connection to $ip on port $porta" -ForegroundColor Green
            } else {
                Write-Host "Connection fail to $ip on port $porta" -ForegroundColor Red
            }

            # Asks if the user wants to take a new test or return to the main menu
            $response = Read-Host "Do you want to take a new test? (y/n)"
            
        } while ($response -eq "y")
    }
    
    TestConnection

}


# Function for Option 3
# Function for Option 3
function Option-3 {
    Write-Host ""
    
    function ValidateServerRules { 
        function Get-InstalledFeatures {
            try {
                # Get installed roles
                $installedFeatures = Get-WindowsFeature | Where-Object { $_.Installed -eq $true }

                # Extract function names and store them in a list
                $featureNames = $installedFeatures | Select-Object -ExpandProperty Name

                # Return the list of names of installed functions
                return $featureNames
            }
            catch {
                Write-Error "An error occurred while getting the roles installed: $_"
            }
        }

        # Calls the function to get the installed functions and stores the result in a variable
        $installedFeatureNames = Get-InstalledFeatures

        Write-Host "Windows Roles/Features" -ForegroundColor Yellow
        Write-Host "https://learn.microsoft.com/en-us/windows-server/administration/server-core/server-core-roles-and-services"

        $RequiredFeatures = @(@('Web Server', 'Web-WebServer'),
                              @('Common HTTP Features', 'Web-Common-Http'),
                              @('Default Document', 'Web-Default-Doc'),
                              @('Directory Browsing', 'Web-Dir-Browsing'),
                              @('HTTP Errors', 'Web-Http-Errors'),
                              @('Static Content', 'Web-Static-Content'),
                              @('Performance', 'Web-Performance'),
                              @('Static Compression', 'Web-Stat-Compression'),
                              @('Security', 'Web-Security'),
                              @('Filtering', 'Web-Filtering'),
                              @('Windows Authentication', 'Web-Windows-Auth'),
                              @('Health', 'Web-Health'),
                              @('HTTP Logging', 'Web-Http-Logging'),
                              @('Application Development', 'Web-App-Dev'),
                              @('NET Extensibility 4.5', 'Web-Net-Ext45'),
                              @('ASP.NET 4.5', 'Web-Asp-Net45'),
                              @('ISAPI Extensions', 'Web-ISAPI-Ext'),
                              @('ISAPI Filters', 'Web-ISAPI-Filter'),
                              @('WebSockets', 'Web-WebSockets'),
                              @('Management Tools', 'Web-Mgmt-Tools'),
                              @('.NET Framework 4.6', 'NET-Framework-45-Core'),
                              @('ASP.NET 4.6', 'NET-Framework-45-ASPNET'),
                              @('WCF Services', 'NET-WCF-Services45'),
                              @('TCP Port Sharing', 'NET-WCF-TCP-PortSharing45'),
                              @('Windows PowerShell', 'PowerShellRoot'),
                              @('Windows PowerShell 5.1', 'PowerShell'),
                              @('Windows PowerShell ISE', 'PowerShell-ISE'))                        
                              

        foreach ($item in $RequiredFeatures) {
            if ($installedFeatureNames -contains $item[1]) {
                Write-Host "Is [$($item[0])] installed: YES"  -ForegroundColor Green
            } else {
                Write-Host "Is [$($item[0])] installed: NO"   -ForegroundColor Red
            }    
        }
    }

    function ValidateInstalledSoftwares{
        Write-Host ""
        Write-Host "Required Softwares" -ForegroundColor Yellow

        $packageList = Get-Package | Select-Object -Property Name, Version, ProviderName
        #$packageList = Get-Package | Select-Object -Property Name

        $SoftwaresRequired = @("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135",
                                "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.38.33135",
                               "Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161")

        
        foreach ($item in $SoftwaresRequired) {
            if ($packageList.Name -contains $item) {
                Write-Host "Is [$($item)] installed: YES"  -ForegroundColor Green
            } else {
                Write-Host "Is [$($item)] installed: NO"   -ForegroundColor Red
            }    
        }
    }


    function Get-Administrators{
        Write-Host ""
        $adminGroupMembers = Get-LocalGroupMember -Group "Administrators"
        Write-host "Administrator Users/Groups" -ForegroundColor Yellow
        foreach ($item in $adminGroupMembers) {
                Write-Host "$($item)"
            }    
    }

    function GetLogonAsaService{
        # Sets the policy file path
            $seceditOutputPath = "$env:TEMP\seceditExport.inf"

            # Exporta as políticas locais para um arquivo
            secedit /export /cfg $seceditOutputPath /quiet

            # Lê o conteúdo do arquivo de política
            $seceditContent = Get-Content -Path $seceditOutputPath

            # Encontra a linha que contém as permissões de "Logon as a service"
            $logonAsServiceLine = $seceditContent | Select-String -Pattern "SeServiceLogonRight"

            # Extrai os usuários que têm permissão para logar como serviço
            if ($logonAsServiceLine) {
                $logonAsServiceUsers = $logonAsServiceLine -replace "SeServiceLogonRight\s*=\s*", ""
                $logonAsServiceUsers = $logonAsServiceUsers -split ","
                
                Write-Host "Usuários com permissão para logar como serviço:"
                foreach ($user in $logonAsServiceUsers) {
                    Write-Host $user.Trim()
                }
            } else {
                Write-Host "Nenhuma configuração encontrada para 'Logon as a service'."
            }

            # Remove o arquivo de política exportado
            Remove-Item -Path $seceditOutputPath
    }

    function UsersInReplaceProcessLevelToken {
        # Sets the policy file path
            $seceditOutputPath = "$env:TEMP\seceditExport.inf"

            # Exporta as políticas locais para um arquivo
            secedit /export /cfg $seceditOutputPath /quiet

            # Lê o conteúdo do arquivo de política
            $seceditContent = Get-Content -Path $seceditOutputPath

            # Encontra a linha que contém as permissões de "Replace a process level token"
            $replaceTokenPrivilegeLine = $seceditContent | Select-String -Pattern "SeAssignPrimaryTokenPrivilege"

            # Extrai os usuários e grupos que têm permissão para "Replace a process level token"
            if ($replaceTokenPrivilegeLine) {
                $replaceTokenPrivilegeUsers = $replaceTokenPrivilegeLine -replace "SeAssignPrimaryTokenPrivilege\s*=\s*", ""
                $replaceTokenPrivilegeUsers = $replaceTokenPrivilegeUsers -split ","
                
                Write-Host "Usuários e grupos com permissão para 'Replace a process level token':"
                foreach ($user in $replaceTokenPrivilegeUsers) {
                    Write-Host $user.Trim()
                }
            } else {
                Write-Host "Nenhuma configuração encontrada para 'Replace a process level token'."
            }

            # Remove o arquivo de política exportado
            Remove-Item -Path $seceditOutputPath

    }

    ValidateServerRules
    ValidateInstalledSoftwares
    Get-Administrators
    GetLogonAsaService
    UsersInReplaceProcessLevelToken

    
    Pause
}



# Function for Option 4
function Option-4 {
    Write-Host ""
    #$UserName = Read-Host "uSER"
    #Write-Host $UserName
    # Adicione aqui o código que você quer executar para a Opção 4

    function Get-InstalledFeatures {
        try {
             # Obter as funções instaladas
             $installedFeatures = Get-WindowsFeature | Where-Object { $_.Installed -eq $true }

             # Extrair os nomes das funções e armazená-los em uma lista
             $featureNames = $installedFeatures | Select-Object -ExpandProperty Name

             # Retornar a lista de nomes das funções instaladas
             return $featureNames
            }
            catch {
                Write-Error "Ocorreu um erro ao obter as funções instaladas: $_"
            }
        }



        # Chama a função para obter as funções instaladas e armazena o resultado em uma variável
       $installedFeatureNames = Get-InstalledFeatures

       Write-host "Windows Roles/Features" -ForegroundColor yellow
       Write-host "https://learn.microsoft.com/en-us/windows-server/administration/server-core/server-core-roles-and-services"
       $lista = @('Web-Server', 'Web-Default-Doc', 'Web-Dir-Browsing', 'Web-Http-Errors', 'Web-Static-Content', 'Web-Http-Logging', 'Web-Performance', 'Web-Stat-Compression',
       'Web-Security', 'Web-Filtering', 'Web-Windows-Auth', 'Web-Net-Ext45', 'Web-Asp-Net45', 'FS-Resource-Manager')
		
		
        foreach ($item in $lista) {
            if ($installedFeatureNames -contains $item) {
		        Write-Host "Is [$item] installed: YES"  -ForegroundColor Green
		        } else {
		        Write-Host "Is [$item] installed: NO"   -ForegroundColor Red
	        }	
        }



    Pause
}


# Function for Option 5
function Option-5 {
    
    $FilePath = Read-Host "Insert here"
    Write-Host "FILE: $FilePath" -ForegroundColor Green
    

    if (-Not (Test-Path -Path $FilePath)) {
        Write-Error "The specified file does not exist. Please provide a valid path."
    
    }


    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA1
        Write-Host "HASH: $($hash.Hash)" -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred while calculating the hash: $_"
    }


    Pause
}

# Function for Option 6
function Option-6 {
    $FilePath = Read-Host "Insert here"
    Write-Host "FILE: $FilePath" -ForegroundColor Green
    

    if (-Not (Test-Path -Path $FilePath)) {
        Write-Error "The specified file does not exist. Please provide a valid path."
    
    }


    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
        Write-Host "HASH: $($hash.Hash)" -ForegroundColor Green
    }
    catch {
        Write-Error "OAn error occurred while calculating the hash: $_"
    }
    Pause
}

# # Function for Option 7
function Option-7 {
    Write-Output "Current User: $(whoami)"
    write-Output "FQDN: $((Get-WmiObject Win32_ComputerSystem).Name).$((Get-WmiObject Win32_ComputerSystem).Domain)"

    function GetOsDetails {
        $computerInfo = Get-ComputerInfo
        Write-Output "WINDOWS PRODUCT NAME: $($computerInfo.WindowsProductName)"
        #Write-Output "WindowsProductName $computerInfo.WindowsVersion"
        #Write-Output $computerInfo.CsNumberOfProcessors
        #Write-Output $computerInfo.CsNumberOfLogicalProcessors
        #Write-Output $computerInfo.CsProcessors
        #Write-Output $computerInfo.CsTotalPhysicalMemory
        ##Write-Output $computerInfo.CsPhyicallyInstalledMemory
        #Write-Output $computerInfo.OsVersion
        #Write-Output $computerInfo.OsLocalDateTime
        ##Write-Output $computerInfo.OsLocalDateTime
        #Write-Output $computerInfo.OsUptime
        #Write-Output $computerInfo.OsInstallDate
        #Write-Output $computerInfo.OsLanguage
        #Write-Output $computerInfo.LogonServer
          
    }

    
    GetOsDetails
    Write-Host ""
    Pause
}


# Function to pause execution and wait for the user to press a key
function Pause {
    Write-Host "Press any key to continue...`n" -NoNewline
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Clear-Host
}

# Main menu loop
do {
    $choice = Show-Menu

    switch ($choice) {
        "1" {
            
            Option-1
        }
        "2" {
            Option-2
        }        
        "3" {
            Option-3
        }        
        "4" {
            Option-4
        }
        "5" {
            Option-5
        }
        "6" {
            Option-6
        }
        "7" {
            Option-7
        }
        "0" {
            Write-Host "Quiting..."
        }
        default {
            Write-Host "Invalid option. Try again..."
            Pause
        }
    }
} while ($choice -ne "0")




# Get-Package | Select-Object -Property Name, Version, ProviderName


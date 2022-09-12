# Automated SCCM Deployment

### Prerequisites
- Assessment and Deployment Kit
- Assessment and Deployment Kit Preinstallation Environment
- Microsoft Deployment Toolkit
- Microsoft SQL Server
- System Center Configuration Manager

### STEP 01
Server Manager > Roles > Add Roles  
Select Active Directory Domain Services
When finished launch dcpromo.exe  
Select Use advanced mode installation  
Create a new domain in a new forest  
Enter FQDN of the forest root domain  
Enter the NETBIOS name  
Slect the Forest functional level  
Select DNS server and Global catalog  
Enter password
Select Reboot on completion  

### STEP 02
Server Manager > Roles > Add Roles  
Select DHCP Server  
WINS is not required for applications on this network


### STEP 03
Log on to the Domain Controller with Administrator account.  
Server Manager > Tools > ADSI  
Right-click ADSI Edit > Click OK

### STEP 04

### STEP 05

### STEP 06

### STEP 07

### STEP 08

### STEP 09

### STEP 10

**BUG Author: [Ravi Sharma]**

**Product Information:**

- Vendor Homepage: (https://phpgurukul.com/student-record-system-php/)
- Affected Version: [<= v1.0]
- BUG Author: Ravi Sharma

**Vulnerability Details**

- Type: Authentication Bypass SQL Injection
- Affected URL: http://localhost/studentrecordms/login.php
- Vulnerable Parameter:  Login page (Username and Password)- Authentication bypass - able to login without valid credentials

**Vulnerable Files:**

- File Name: Login.php
- Path: /studentrecordms/login.php

**Vulnerability Type**

- SQL Injection Vulnerability (CWE-89: Authentication Bypass)
- Severity Level: CRITICAL (CVSS: 9.1)

**Root Cause:**
A critical SQL injection vulnerability exists in the login functionality of Student Record System allowing authentication bypass. The code directly concatenates user input into SQL query strings without any parameterisation or input validation, allowing attackers to inject malicious SQL code. **_Line 8 is causing the vulnerability_**

<img width="959" height="318" alt="Image" src="https://github.com/user-attachments/assets/0cf5e985-b777-44cb-bda2-9a66d3ca93ca" />

**Impact:**

- Bypass authentication completely
- Access any user account without credentials
- Gain administrative access

**Description:**
-------------------------------------------------------------------------------------------------------------------------------------

**1. Vulnerability Details:**
The login functionality in [specific file, e.g., login.php] does not  properly sanitize user input before using it in SQL queries. This  allows an attacker to inject malicious SQL code through the username parameter.

**Vulnerable Code Example**
`$query=mysqli_query($con,"select ID,loginid from tbl_login where  loginid='$uname' && password='$Password' "); `

<img width="1475" height="314" alt="Image" src="https://github.com/user-attachments/assets/93f6f6af-b59a-499f-adc3-e6d8092d1e97" />

**Step-by-Step Reproduction**
1. Navigate to the login page: http://localhost/studentrecordms/login.php 
2. In the username field, enter: 1 'or' 1=1--
3. In the password field, enter any value or paste the same payload 1 'or' 1=1--
4. Click the login button
5. Observe successful authentication bypass

**Screenshots**
[Attach screenshots showing:]
- Login page with injected payload
- Successful bypass (dashboard/admin panel access)
<img width="1719" height="643" alt="Image" src="https://github.com/user-attachments/assets/e965f2d7-948a-46ab-a86c-0a89d953501f" />

<img width="1731" height="820" alt="Image" src="https://github.com/user-attachments/assets/5fd32d66-2baa-4257-a637-d9167f23567b" />

**Impact Assessment**
An attacker can:
- Bypass authentication completely
- Access any user account without credentials
- Gain administrative access
- Access sensitive data in the database
- Potentially modify or delete data
- Launch further attacks on the system

**Affected Components**
- User authentication system
- Admin authentication system
- Any other login forms in the application

**Remediation Recommendations**
**Immediate Fix**
1. Use prepared statements (parameterized queries)
2. Implement input validation
3. Apply principle of least privilege for database accounts

**Secure Code Example**
```php
// Use PDO with prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
$user = $stmt->fetch();

**References**

- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection 
- CWE-89: https://cwe.mitre.org/data/definitions/89.html 
- Implement logging and monitoring mechanisms

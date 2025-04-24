# This step is to install the web application for Snort
# in order to test SQL injection attacks

# Install Apache and PHP
dnf install httpd php php-mysqlnd mariadb-server -y

# Start and enable services
systemctl enable --now httpd
systemctl enable --now mariadb

# Secure MariaDB installation
mysql_secure_installation

# Create a database for testing
mysql -u root -p -e "CREATE DATABASE testdb; CREATE USER 'testuser'@'localhost' IDENTIFIED BY 'password'; GRANT ALL ON testdb.* TO 'testuser'@'localhost'; FLUSH PRIVILEGES;"


# Create a simple PHP web app
cat > /var/www/html/vulnerable.php << 'EOF'
<?php
// This is a deliberately vulnerable script for testing SQL injection detection
$servername = "localhost";
$username = "testuser";
$password = "password";
$dbname = "testdb";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Vulnerable code - no input sanitization
if(isset($_GET['id'])) {
    $id = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id = $id";
    echo "Executing query: $sql";

    // For demonstration only - don't actually execute the query
    echo "<p>This is a demonstration of a vulnerable query.</p>";
}
?>

<form method="GET">
    <input type="text" name="id" placeholder="Enter user ID">
    <input type="submit" value="Submit">
</form>
EOF

# Set permissions for the web app
chown -R apache:apache /var/www/html/
chmod -R 755 /var/www/html/


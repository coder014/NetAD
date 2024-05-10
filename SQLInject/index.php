<!-- index.php -->
<html>
<head>
    <title>Login</title>
</head>
<body>
    <form action="index.php" method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>

    <?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'];
        $password = $_POST['password'];

        // 模拟数据库查询
        $db = new PDO('sqlite:users.db');
        $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
        $result = $db->query($query);

        if ($result && $row = $result->fetch()) {
            echo "Login successful. Welcome, " . $row['username'] . ".";
        } else {
            echo "Login failed.";
        }
    }
    ?>
</body>
</html>
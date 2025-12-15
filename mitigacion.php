<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Administración - TechCorp (SEGURO)</title>
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
        
        .warning-banner {
            background: #ffeb3b;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
            font-weight: bold;
            border: 2px solid #ffc107;
        }
        
        .security-banner {
            background: #d4edda;
            color: #155724;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
            font-weight: bold;
            border: 2px solid #c3e6cb;
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
                <p>v2.1.4 - SEGURO</p>
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
                <p>✅ <strong>SISTEMA SEGURO:</strong></p>
                <p>Todas las vulnerabilidades han sido corregidas.</p>
            </div>
        </div>
        
        <!-- Panel derecho -->
        <div class="right-panel">
            <!-- Banner de seguridad -->
            <div class="security-banner">
                ✅ SISTEMA SEGURO - Command Injection mitigado ✅
            </div>
            
            <!-- Tabs de navegación -->
            <div class="nav-tabs">
                <div class="tab active" onclick="switchTab('login')">🔐 Login</div>
                <div class="tab" onclick="switchTab('tools')">🛠️ Herramientas</div>
                <div class="tab" onclick="switchTab('system')">💻 Sistema</div>
                <div class="tab" onclick="switchTab('help')">❓ Ayuda</div>
            </div>
            
            <!-- Contenido de Login - CORREGIDO -->
            <div id="login" class="tab-content active">
                <h1>Acceso al Sistema</h1>
                <h2>Autenticación de Administrador</h2>
                
                <?php
                session_start();
                
                // FUNCIONES DE SEGURIDAD
                function sanitize_input($input) {
                    $input = trim($input);
                    $input = stripslashes($input);
                    $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
                    return $input;
                }
                
                function validate_username($username) {
                    // Solo letras, números, puntos y guiones bajos
                    return preg_match('/^[a-zA-Z0-9._-]{3,20}$/', $username);
                }
                
                function validate_password($password) {
                    // Mínimo 8 caracteres
                    return strlen($password) >= 8;
                }
                
                // Login SEGURO
                if (isset($_POST['login'])) {
                    $username = sanitize_input($_POST['username']);
                    $password = $_POST['password']; // No sanitizar contraseñas
                    
                    // VALIDACIÓN
                    if (!validate_username($username)) {
                        echo '<div class="alert alert-danger">Formato de usuario inválido</div>';
                    } elseif (!validate_password($password)) {
                        echo '<div class="alert alert-danger">Contraseña debe tener al menos 8 caracteres</div>';
                    } else {
                        // Autenticación SEGURA sin ejecución de comandos
                        $users = [
                            'admin' => password_hash('password123', PASSWORD_DEFAULT)
                        ];
                        
                        if (array_key_exists($username, $users) && 
                            password_verify($password, $users[$username])) {
                            $_SESSION['user'] = $username;
                            $_SESSION['login_time'] = time();
                            echo '<div class="alert alert-success">Login exitoso</div>';
                        } else {
                            echo '<div class="alert alert-danger">Credenciales incorrectas</div>';
                        }
                    }
                }
                
                // Mostrar info si hay sesión
                if (isset($_SESSION['user'])) {
                    echo '<div class="user-info">';
                    echo "✅ Usuario autenticado: <strong>" . htmlspecialchars($_SESSION['user']) . "</strong>";
                    echo ' | <a href="?logout=1" style="color: white; text-decoration: underline;">Cerrar sesión</a>';
                    echo '</div>';
                }
                
                // Logout
                if (isset($_GET['logout'])) {
                    session_destroy();
                    echo '<div class="alert alert-success">Sesión cerrada. Recarga la página.</div>';
                }
                ?>
                
                <form method="POST" action="">
                    <div class="form-group">
                        <label for="username">👤 Usuario:</label>
                        <input type="text" id="username" name="username" 
                               placeholder="admin" 
                               pattern="[a-zA-Z0-9._-]{3,20}"
                               title="Solo letras, números, puntos, guiones y guiones bajos (3-20 caracteres)"
                               required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">🔒 Contraseña:</label>
                        <input type="password" id="password" name="password" 
                               placeholder="password123" 
                               minlength="8"
                               title="Mínimo 8 caracteres"
                               required>
                    </div>
                    
                    <button type="submit" name="login">🚀 Iniciar Sesión</button>
                </form>
                
                <div class="payload-box" style="background: #d4edda;">
                    <strong>🛡️ Protecciones implementadas:</strong><br>
                    <code>✓ Validación con regex</code><br>
                    <code>✓ Sanitización de inputs</code><br>
                    <code>✓ Password hashing (bcrypt)</code><br>
                    <code>✓ Sin ejecución de shell en login</code>
                </div>
            </div>
            
            <!-- Contenido de Herramientas - CORREGIDO -->
            <div id="tools" class="tab-content">
                <h1>🛠️ Herramientas del Sistema</h1>
                <h2>Utilidades de administración</h2>
                
                <?php
                // Verificar si está logueado
                if (!isset($_SESSION['user'])) {
                    echo '<div class="alert alert-danger">Debe iniciar sesión primero</div>';
                } else {
                    // FUNCIONES SEGURAS
                    function validate_host($host) {
                        // Validar hostname o IP
                        if (filter_var($host, FILTER_VALIDATE_IP)) {
                            return true;
                        }
                        // Validar hostname
                        return preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/', $host);
                    }
                    
                    function validate_domain($domain) {
                        return preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/', $domain);
                    }
                    
                    function safe_ping($host) {
                        if (!validate_host($host)) {
                            return "Host no válido";
                        }
                        // ESCAPAR ARGUMENTOS
                        $safe_host = escapeshellarg($host);
                        return shell_exec("ping -c 4 " . $safe_host . " 2>&1");
                    }
                    
                    function safe_nslookup($domain) {
                        if (!validate_domain($domain)) {
                            return "Dominio no válido";
                        }
                        // ESCAPAR ARGUMENTOS
                        $safe_domain = escapeshellarg($domain);
                        return shell_exec("nslookup " . $safe_domain . " 2>&1");
                    }
                    
                    // Ping SEGURO
                    if (isset($_POST['ping'])) {
                        $host = sanitize_input($_POST['host']);
                        
                        echo '<div class="section">';
                        echo "<h3>📡 Ping a: " . htmlspecialchars($host) . "</h3>";
                        
                        $output = safe_ping($host);
                        
                        echo '<div class="result-box">';
                        echo htmlspecialchars($output) ?: "No hay respuesta";
                        echo '</div>';
                        echo '</div>';
                    }
                    
                    // DNS Lookup SEGURO
                    if (isset($_POST['nslookup'])) {
                        $domain = sanitize_input($_POST['domain']);
                        
                        echo '<div class="section">';
                        echo "<h3>🔍 DNS Lookup: " . htmlspecialchars($domain) . "</h3>";
                        
                        $output = safe_nslookup($domain);
                        
                        echo '<div class="result-box">';
                        echo htmlspecialchars($output) ?: "No se encontró el dominio";
                        echo '</div>';
                        echo '</div>';
                    }
                }
                ?>
                
                <?php if (isset($_SESSION['user'])): ?>
                <div class="section">
                    <h3>📡 Prueba de Conectividad</h3>
                    <form method="POST">
                        <div class="form-group">
                            <label for="host">Dirección IP o Host:</label>
                            <input type="text" id="host" name="host" 
                                   placeholder="google.com o 8.8.8.8" 
                                   pattern="^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+)|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
                                   title="Hostname válido o dirección IPv4"
                                   required>
                        </div>
                        <button type="submit" name="ping">✅ Ejecutar Ping</button>
                    </form>
                    
                    <div class="payload-box" style="background: #d4edda;">
                        <strong>🛡️ Protecciones:</strong><br>
                        <code>✓ escapeshellarg()</code><br>
                        <code>✓ Validación con regex</code><br>
                        <code>✓ Pattern en HTML5</code>
                    </div>
                </div>
                
                <div class="section">
                    <h3>🔍 Búsqueda DNS</h3>
                    <form method="POST">
                        <div class="form-group">
                            <label for="domain">Nombre de Dominio:</label>
                            <input type="text" id="domain" name="domain" 
                                   placeholder="ejemplo.com"
                                   pattern="^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
                                   title="Formato de dominio válido"
                                   required>
                        </div>
                        <button type="submit" name="nslookup">🔎 Buscar DNS</button>
                    </form>
                    
                    <div class="payload-box" style="background: #d4edda;">
                        <strong>🛡️ Protecciones:</strong><br>
                        <code>✓ escapeshellarg()</code><br>
                        <code>✓ Validación estricta de dominio</code><br>
                        <code>✓ Sanitización previa</code>
                    </div>
                </div>
                <?php endif; ?>
            </div>
            
            <!-- Contenido de Sistema - CORREGIDO -->
            <div id="system" class="tab-content">
                <h1>💻 Información del Sistema</h1>
                <h2>Monitoreo y Estadísticas</h2>
                
                <?php
                // Verificar si está logueado
                if (!isset($_SESSION['user'])) {
                    echo '<div class="alert alert-danger">Debe iniciar sesión primero</div>';
                } else {
                    // LISTA BLANCA de comandos permitidos
                    $allowed_commands = [
                        'whoami' => 'Usuario actual',
                        'pwd' => 'Directorio actual',
                        'uname -a' => 'Información del sistema',
                        'df -h' => 'Espacio en disco',
                        'free -h' => 'Memoria libre',
                        'date' => 'Fecha y hora',
                        'uptime' => 'Tiempo de actividad'
                    ];
                    
                    // Comandos personalizados SEGUROS
                    if (isset($_POST['custom_cmd'])) {
                        $selected_cmd = sanitize_input($_POST['custom_command']);
                        
                        echo '<div class="section">';
                        echo "<h3>⚡ Comando ejecutado: " . htmlspecialchars($selected_cmd) . "</h3>";
                        
                        // Validar contra lista blanca
                        if (array_key_exists($selected_cmd, $allowed_commands)) {
                            // Ejecutar de forma segura con escapeshellcmd
                            $output = shell_exec(escapeshellcmd($selected_cmd) . " 2>&1");
                            
                            echo '<div class="result-box">';
                            echo htmlspecialchars($output) ?: "Comando ejecutado (sin output)";
                            echo '</div>';
                        } else {
                            echo '<div class="alert alert-danger">Comando no permitido</div>';
                        }
                        echo '</div>';
                    }
                }
                ?>
                
                <?php if (isset($_SESSION['user'])): ?>
                <div class="section">
                    <h3>📊 Estado del Sistema</h3>
                    <?php
                    foreach ($allowed_commands as $cmd => $desc) {
                        echo "<h4>$desc:</h4>";
                        $output = shell_exec(escapeshellcmd($cmd) . " 2>&1");
                        echo '<div class="result-box">' . htmlspecialchars($output) . '</div>';
                    }
                    ?>
                </div>
                
                <div class="section">
                    <h3>⚡ Comando Personalizado (Restringido)</h3>
                    <form method="POST">
                        <div class="form-group">
                            <label for="custom_command">Comando permitido:</label>
                            <select id="custom_command" name="custom_command" required>
                                <option value="">-- Seleccione comando --</option>
                                <?php foreach ($allowed_commands as $cmd => $desc): ?>
                                    <option value="<?php echo htmlspecialchars($cmd); ?>">
                                        <?php echo htmlspecialchars($desc); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <button type="submit" name="custom_cmd">🚀 Ejecutar Comando</button>
                    </form>
                    
                    <div class="payload-box" style="background: #d4edda;">
                        <strong>🛡️ Protecciones:</strong><br>
                        <code>✓ Lista blanca de comandos</code><br>
                        <code>✓ Select en lugar de input libre</code><br>
                        <code>✓ escapeshellcmd()</code><br>
                        <code>✓ Sanitización previa</code>
                    </div>
                </div>
                <?php endif; ?>
            </div>
            
            <!-- Contenido de Ayuda - ACTUALIZADO -->
            <div id="help" class="tab-content">
                <h1>❓ Centro de Ayuda</h1>
                <h2>Guía de seguridad implementada</h2>
                
                <div class="section">
                    <h3>🛡️ Medidas de Seguridad Implementadas</h3>
                    
                    <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                        <tr style="background: #667eea; color: white;">
                            <th style="padding: 10px;">Vulnerabilidad</th>
                            <th style="padding: 10px;">Solución</th>
                            <th style="padding: 10px;">Código implementado</th>
                        </tr>
                        <tr style="border-bottom: 1px solid #ddd;">
                            <td style="padding: 10px;">Command Injection en Login</td>
                            <td style="padding: 10px;">Validación + Sanitización</td>
                            <td style="padding: 10px;"><code>preg_match() + htmlspecialchars()</code></td>
                        </tr>
                        <tr style="border-bottom: 1px solid #ddd;">
                            <td style="padding: 10px;">Command Injection en Ping</td>
                            <td style="padding: 10px;">Escapado de argumentos</td>
                            <td style="padding: 10px;"><code>escapeshellarg()</code></td>
                        </tr>
                        <tr style="border-bottom: 1px solid #ddd;">
                            <td style="padding: 10px;">Command Injection en DNS</td>
                            <td style="padding: 10px;">Validación + Escapado</td>
                            <td style="padding: 10px;"><code>validate_domain() + escapeshellarg()</code></td>
                        </tr>
                        <tr style="border-bottom: 1px solid #ddd;">
                            <td style="padding: 10px;">Command Injection en Comandos</td>
                            <td style="padding: 10px;">Lista blanca</td>
                            <td style="padding: 10px;"><code>$allowed_commands + select</code></td>
                        </tr>
                        <tr>
                            <td style="padding: 10px;">XSS (Cross-Site Scripting)</td>
                            <td style="padding: 10px;">Sanitización de output</td>
                            <td style="padding: 10px;"><code>htmlspecialchars()</code></td>
                        </tr>
                    </table>
                    
                    <h3>✅ Funciones de seguridad PHP utilizadas:</h3>
                    <div class="payload-box" style="background: #d4edda; color: #155724;">
                        <strong>1. htmlspecialchars()</strong> - Escapa HTML en output<br>
                        <strong>2. escapeshellarg()</strong> - Escapa argumentos de shell<br>
                        <strong>3. escapeshellcmd()</strong> - Escapa comandos de shell<br>
                        <strong>4. preg_match()</strong> - Validación con regex<br>
                        <strong>5. password_hash()</strong> - Hash seguro de contraseñas<br>
                        <strong>6. password_verify()</strong> - Verificación de contraseñas<br>
                        <strong>7. filter_var()</strong> - Validación de IPs<br>
                        <strong>8. trim() + stripslashes()</strong> - Limpieza básica
                    </div>
                    
                    <h3>📚 Recursos de aprendizaje:</h3>
                    <ul style="margin-left: 20px;">
                        <li><a href="https://owasp.org/www-community/attacks/Command_Injection">OWASP Command Injection</a></li>
                        <li><a href="https://www.php.net/manual/es/function.escapeshellarg.php">PHP: escapeshellarg()</a></li>
                        <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html">OWASP Input Validation</a></li>
                    </ul>
                </div>
                
                <div class="section">
                    <h3>🔄 Configurar Sistema Seguro en Kali</h3>
                    <div class="result-box">
                        # 1. Instalar Apache y PHP<br>
                        sudo apt update && sudo apt install apache2 php libapache2-mod-php -y<br><br>
                        
                        # 2. Copiar este archivo SEGURO<br>
                        sudo nano /var/www/html/seguro.php<br>
                        # Pegar este código y guardar<br><br>
                        
                        # 3. Configurar php.ini para seguridad<br>
                        sudo nano /etc/php/8.2/apache2/php.ini<br>
                        # Añadir: disable_functions = exec,passthru,shell_exec,system<br><br>
                        
                        # 4. Iniciar servicio<br>
                        sudo systemctl restart apache2<br><br>
                        
                        # 5. Acceder en:<br>
                        http://localhost/seguro.php
                    </div>
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
        
        window.onload = function() {
            console.log("Sistema seguro cargado - Todas las vulnerabilidades mitigadas");
        }
    </script>
</body>
</html>
#!/usr/bin/env python3
"""
HexGuard Security Hardening Toolkit
====================================
HexGuard es una herramienta de hardening automatizado para sistemas Linux.

Funcionalidades principales:
  - Actualización del sistema operativo
  - Configuración del firewall UFW
  - Endurecimiento de SSH (sshd_config)
  - Instalación y activación de Fail2Ban
  - Escaneo de rootkits con chkrootkit
  - Auditoría de cuentas de usuario
  - Deshabilitación de servicios inseguros (telnet, rsh, ftp...)
  - Verificación y corrección de permisos en archivos críticos
  - Análisis de logs de autenticación SSH

ADVERTENCIA:
    Este script modifica configuraciones sensibles del sistema operativo.
    DEBE ejecutarse con privilegios de superusuario (root):

        sudo python3 hexguard.py

    Ejecutarlo sin root provocará fallos silenciosos o errores de permiso.

Autor: lucasfoking
"""

# ──────────────────────────────────────────────
# Importación de módulos estándar de Python
# ──────────────────────────────────────────────
import argparse
import datetime
import logging
import os
import shutil
import subprocess
import sys

# ──────────────────────────────────────────────
# Configuración del sistema de logging
# ──────────────────────────────────────────────
logging.basicConfig(
    filename="hexguard.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    encoding="utf-8",
)


# ──────────────────────────────────────────────
# Banner con careta de Anonymous en ASCII art
# ──────────────────────────────────────────────
def banner():
    """Limpia la pantalla y muestra el banner con la careta de Anonymous."""
    os.system("clear")
    print(r"""
         ─────▄██▀▀▀▀▀▀▀▀▀▀▀▀▀██▄─────
         ────███───────────────███────
         ───███─────────────────███───
         ──███───▄▀▀▄─────▄▀▀▄───███──
         ─████─▄▀────▀▄─▄▀────▀▄─████─
         ─████──▄████─────████▄──█████
         █████─██▓▓▓██───██▓▓▓██─█████
         █████─██▓█▓██───██▓█▓██─█████
         █████─██▓▓▓█▀─▄─▀█▓▓▓██─█████
         ████▀──▀▀▀▀▀─▄█▄─▀▀▀▀▀──▀████
         ███─▄▀▀▀▄────███────▄▀▀▀▄─███
         ███──▄▀▄─█──█████──█─▄▀▄──███
         ███─█──█─█──█████──█─█──█─███
         ███─█─▀──█─▄█████▄─█──▀─█─███
         ███▄─▀▀▀▀──█─▀█▀─█──▀▀▀▀─▄███
         ████─────────────────────████
         ─███───▀█████████████▀───████
         ─███───────█─────█───────████
         ─████─────█───────█─────█████
         ───███▄──█────█────█──▄█████─
         ─────▀█████▄▄███▄▄█████▀─────
         ──────────█▄─────▄█──────────
         ──────────▄█─────█▄──────────
         ───────▄████─────████▄───────
         ─────▄███████───███████▄─────
         ───▄█████████████████████▄───
         ─▄███▀───███████████───▀███▄─
         ███▀─────███████████─────▀███
         ▌▌▌▌▒▒───███████████───▒▒▐▐▐▐
         ─────▒▒──███████████──▒▒─────
         ──────▒▒─███████████─▒▒──────
         ───────▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒───────
         ─────────████░░█████─────────
         ────────█████░░██████────────
         ──────███████░░███████───────
         ─────█████──█░░█──█████──────
         ─────█████──████──█████──────
         ──────████──████──████───────
         ──────████──████──████───────
         ──────████───██───████───────
         ──────████───██───████───────
         ──────████──████──████───────
         ─██────██───████───██─────██─
         ─██───████──████──████────██─
         ─███████████████████████████─
         ─██─────────████──────────██─
         ─██─────────████──────────██─
         ────────────████─────────────
         ─────────────██──────────────

    ██╗  ██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
    ██║  ██║██╔════╝╚██╗██╔╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ███████║█████╗   ╚███╔╝ ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██╔══██║██╔══╝   ██╔██╗ ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ██║  ██║███████╗██╔╝ ██╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝

          HexGuard Security Hardening Toolkit  |  Advanced Linux Protection
                           We are Anonymous. We do not forgive.
                              Created by lucasfoking
""")


# ──────────────────────────────────────────────
# Función principal para ejecutar comandos shell
# ──────────────────────────────────────────────
def run(cmd, descripcion=""):
    """
    Ejecuta un comando del sistema de forma segura.
    Registra el inicio y el resultado en el log.

    Args:
        cmd (str): Comando a ejecutar en la shell.
        descripcion (str): Descripción legible del comando para el log.

    Returns:
        bool: True si el comando tuvo éxito, False si falló.
    """
    etiqueta = descripcion if descripcion else cmd
    print(f"\n  [+] Ejecutando: {etiqueta}")
    logging.info("CMD: %s", cmd)

    resultado = subprocess.run(
        cmd,
        shell=True,
        capture_output=False,
        text=True,
        check=False,   # El retorno se comprueba manualmente a continuación
    )

    if resultado.returncode != 0:
        print(f"  [!] Error al ejecutar: {etiqueta} (código {resultado.returncode})")
        logging.error("FALLO [%d]: %s", resultado.returncode, cmd)
        return False

    logging.info("OK: %s", cmd)
    return True


# ──────────────────────────────────────────────
# Verificación de privilegios root
# ──────────────────────────────────────────────
def check_root():
    """
    Verifica que el script se esté ejecutando con privilegios de superusuario.
    Sin root, muchas operaciones de hardening fallarían silenciosamente.
    """
    if os.geteuid() != 0:
        print("\n  [!] Este script debe ejecutarse como root.")
        print("      Uso: sudo python3 hexguard.py\n")
        sys.exit(1)


# ──────────────────────────────────────────────
# Verificación de herramientas disponibles
# ──────────────────────────────────────────────
def verificar_herramienta(nombre):
    """
    Verifica si un programa/comando está disponible en el sistema.

    Args:
        nombre (str): Nombre del ejecutable a buscar (ej. 'ufw', 'fail2ban').

    Returns:
        bool: True si el programa está instalado, False si no.
    """
    return shutil.which(nombre) is not None


# ──────────────────────────────────────────────
# Función 1: Actualización del sistema
# ──────────────────────────────────────────────
def update_system():
    """
    Actualiza todos los paquetes del sistema operativo.
    Incluye: actualización de listas, upgrade y limpieza de dependencias huérfanas.
    """
    print("\n  [*] Iniciando actualización del sistema...")
    logging.info("=== INICIO: Actualización del sistema ===")

    run("apt update", "Actualizando lista de repositorios")
    run("apt upgrade -y", "Aplicando actualizaciones de paquetes")
    run("apt autoremove -y", "Eliminando paquetes huérfanos")
    run("apt autoclean", "Limpiando caché de paquetes descargados")

    logging.info("=== FIN: Actualización del sistema ===")
    print("\n  [✓] Sistema actualizado correctamente.")


# ──────────────────────────────────────────────
# Función 2: Configuración del firewall UFW
# ──────────────────────────────────────────────
def firewall():
    """
    Instala y configura UFW (Uncomplicated Firewall).
    Política por defecto: bloquear todo el tráfico entrante, permitir el saliente.
    Solo se abren los puertos necesarios: SSH (22), HTTP (80), HTTPS (443).
    """
    print("\n  [*] Configurando firewall UFW...")
    logging.info("=== INICIO: Configuración de firewall ===")

    run("apt install ufw -y", "Instalando UFW")
    run("ufw default deny incoming", "Bloqueando tráfico entrante por defecto")
    run("ufw default allow outgoing", "Permitiendo tráfico saliente por defecto")
    run("ufw allow ssh", "Permitiendo SSH (puerto 22)")
    run("ufw allow http", "Permitiendo HTTP (puerto 80)")
    run("ufw allow https", "Permitiendo HTTPS (puerto 443)")
    run("ufw --force enable", "Activando el firewall")
    run("ufw status verbose", "Mostrando estado del firewall")

    logging.info("=== FIN: Configuración de firewall ===")
    print("\n  [✓] Firewall configurado y activo.")


# ──────────────────────────────────────────────
# Función 3: Hardening de SSH
# ──────────────────────────────────────────────
def ssh_hardening():
    """
    Endurece la configuración del servidor SSH modificando /etc/ssh/sshd_config.

    Cambios aplicados:
      - Deshabilitar login como root
      - Deshabilitar autenticación por contraseña (solo llaves SSH)
      - Reducir el número máximo de intentos de autenticación
      - Deshabilitar reenvío X11
    """
    archivo = "/etc/ssh/sshd_config"
    backup = "/etc/ssh/sshd_config.bak"

    print(f"\n  [*] Aplicando hardening en {archivo}...")
    logging.info("=== INICIO: SSH hardening ===")

    if not os.path.exists(archivo):
        print(f"  [!] No se encontró {archivo}. ¿Está SSH instalado?")
        logging.warning("Archivo no encontrado: %s", archivo)
        return

    try:
        shutil.copy2(archivo, backup)
        print(f"  [+] Backup guardado en {backup}")
        logging.info("Backup creado: %s", backup)
    except OSError as e:
        print(f"  [!] No se pudo crear el backup: {e}")
        logging.error("Error al crear backup de SSH config: %s", e)
        return

    # Mapa de sustituciones: cubre líneas comentadas y activas
    cambios = {
        "#PermitRootLogin yes":        "PermitRootLogin no",
        "PermitRootLogin yes":         "PermitRootLogin no",
        "#PasswordAuthentication yes": "PasswordAuthentication no",
        "PasswordAuthentication yes":  "PasswordAuthentication no",
        "#MaxAuthTries 6":             "MaxAuthTries 3",
        "#X11Forwarding yes":          "X11Forwarding no",
        "X11Forwarding yes":           "X11Forwarding no",
    }

    try:
        with open(archivo, "r", encoding="utf-8") as f:
            contenido = f.read()

        for original, reemplazo in cambios.items():
            if original in contenido:
                contenido = contenido.replace(original, reemplazo)
                logging.info("SSH: '%s' -> '%s'", original, reemplazo)

        with open(archivo, "w", encoding="utf-8") as f:
            f.write(contenido)

        run("systemctl restart ssh", "Reiniciando servicio SSH")
        print("\n  [✓] SSH hardening aplicado correctamente.")

    except PermissionError:
        print("  [!] Permiso denegado al modificar la configuración SSH.")
        logging.error("PermissionError al modificar sshd_config")
    except OSError as e:
        print(f"  [!] Error en SSH hardening: {e}")
        logging.error("Error en SSH hardening: %s", e)

    logging.info("=== FIN: SSH hardening ===")


# ──────────────────────────────────────────────
# Función 4: Instalación de Fail2Ban
# ──────────────────────────────────────────────
def install_fail2ban():
    """
    Instala y activa Fail2Ban para bloquear IPs con demasiados intentos
    de login fallidos.
    """
    print("\n  [*] Instalando Fail2Ban...")
    logging.info("=== INICIO: Instalación Fail2Ban ===")

    run("apt install fail2ban -y", "Instalando Fail2Ban")
    run("systemctl enable fail2ban", "Habilitando Fail2Ban al inicio")
    run("systemctl start fail2ban", "Iniciando servicio Fail2Ban")
    run("fail2ban-client status", "Verificando estado de Fail2Ban")

    logging.info("=== FIN: Instalación Fail2Ban ===")
    print("\n  [✓] Fail2Ban instalado y activo.")


# ──────────────────────────────────────────────
# Función 5: Escaneo de rootkits
# ──────────────────────────────────────────────
def rootkit_scan():
    """
    Instala y ejecuta chkrootkit para detectar rootkits conocidos en el sistema.
    Un rootkit es malware que oculta su presencia modificando el sistema operativo.
    """
    print("\n  [*] Iniciando escaneo de rootkits con chkrootkit...")
    logging.info("=== INICIO: Escaneo de rootkits ===")

    run("apt install chkrootkit -y", "Instalando chkrootkit")
    run("chkrootkit", "Ejecutando escaneo completo de rootkits")

    logging.info("=== FIN: Escaneo de rootkits ===")
    print("\n  [✓] Escaneo de rootkits completado. Revisa el output anterior.")


# ──────────────────────────────────────────────
# Función 6: Auditoría de usuarios
# ──────────────────────────────────────────────
def user_audit():
    """
    Realiza una auditoría de cuentas de usuario en el sistema.
    Muestra todos los usuarios, los que tienen UID 0 (equivalentes a root)
    y los que tienen shell de login activa.
    """
    print("\n  [*] Realizando auditoría de usuarios...")
    logging.info("=== INICIO: Auditoría de usuarios ===")

    print("\n  --- Todos los usuarios del sistema ---")
    run("cut -d: -f1 /etc/passwd", "Listando todos los usuarios")

    print("\n  --- Usuarios con UID 0 (equivalentes a root) ---")
    run("awk -F: '($3 == 0) {print}' /etc/passwd", "Buscando usuarios con UID 0")

    print("\n  --- Usuarios con shell de login activa ---")
    # Se usa -E para expresiones extendidas en lugar de \| (alternancia POSIX básica)
    run(
        "grep -Ev '/sbin/nologin|/bin/false' /etc/passwd | cut -d: -f1,7",
        "Usuarios con shell interactiva",
    )

    print("\n  --- Últimos inicios de sesión registrados ---")
    run("last -n 10", "Mostrando los 10 últimos logins")

    logging.info("=== FIN: Auditoría de usuarios ===")


# ──────────────────────────────────────────────
# Función 7: Deshabilitar servicios inseguros
# ──────────────────────────────────────────────
def disable_services():
    """
    Detiene y deshabilita servicios de red inseguros que transmiten datos
    en texto plano: telnet, rsh, rlogin, vsftpd y ftp.
    """
    print("\n  [*] Deshabilitando servicios inseguros...")
    logging.info("=== INICIO: Deshabilitar servicios inseguros ===")

    servicios = ["telnet", "rsh", "rlogin", "vsftpd", "ftp"]

    for servicio in servicios:
        if verificar_herramienta(servicio) or os.path.exists(f"/etc/init.d/{servicio}"):
            run(f"systemctl stop {servicio}", f"Deteniendo {servicio}")
            run(f"systemctl disable {servicio}", f"Deshabilitando {servicio}")
            logging.info("Servicio deshabilitado: %s", servicio)
        else:
            print(f"  [i] {servicio} no encontrado en el sistema. Omitiendo.")

    logging.info("=== FIN: Deshabilitar servicios inseguros ===")
    print("\n  [✓] Servicios inseguros deshabilitados.")


# ──────────────────────────────────────────────
# Función 8: Verificación de permisos críticos
# ──────────────────────────────────────────────
def permissions():
    """
    Verifica y corrige los permisos de archivos críticos del sistema.

    Permisos esperados:
      /etc/passwd  -> 644 (lectura para todos, escritura solo root)
      /etc/shadow  -> 640 (solo root y grupo shadow pueden leerlo)
      /root        -> 700 (solo root accede a su directorio home)
    """
    print("\n  [*] Verificando permisos de archivos críticos...")
    logging.info("=== INICIO: Verificación de permisos ===")

    run("ls -l /etc/passwd",  "Permisos de /etc/passwd")
    run("ls -l /etc/shadow",  "Permisos de /etc/shadow")
    run("ls -ld /root",       "Permisos del directorio /root")

    print("\n  [*] Aplicando permisos correctos...")

    run("chmod 644 /etc/passwd",          "Corrigiendo permisos de /etc/passwd")
    run("chmod 640 /etc/shadow",          "Corrigiendo permisos de /etc/shadow")
    run("chmod 700 /root",                "Corrigiendo permisos de /root")
    run("chown root:root /etc/passwd",    "Verificando propietario de /etc/passwd")
    run("chown root:shadow /etc/shadow",  "Verificando propietario de /etc/shadow")

    logging.info("=== FIN: Verificación de permisos ===")
    print("\n  [✓] Permisos críticos verificados y corregidos.")


# ──────────────────────────────────────────────
# Función 9: Mostrar logs de intentos SSH fallidos
# ──────────────────────────────────────────────
def show_logs():
    """
    Analiza los logs de autenticación del sistema para mostrar intentos de
    login fallidos por SSH y las IPs con más intentos (posibles ataques de
    fuerza bruta).
    """
    print("\n  [*] Analizando logs de autenticación SSH...")
    logging.info("=== INICIO: Análisis de logs SSH ===")

    log_paths = ["/var/log/auth.log", "/var/log/secure"]
    log_file = next((p for p in log_paths if os.path.exists(p)), None)

    if not log_file:
        print("  [!] No se encontró archivo de log de autenticación.")
        logging.warning("No se encontró auth.log ni /var/log/secure")
        return

    print(f"\n  --- Últimos 20 intentos fallidos de SSH ({log_file}) ---")
    run(
        f"grep 'Failed password' {log_file} | tail -n 20",
        "Mostrando intentos fallidos recientes",
    )

    print("\n  --- IPs con más intentos fallidos (posibles atacantes) ---")
    run(
        f"grep 'Failed password' {log_file} | awk '{{print $11}}'"
        " | sort | uniq -c | sort -rn | head -10",
        "Ranking de IPs atacantes",
    )

    logging.info("=== FIN: Análisis de logs SSH ===")


# ──────────────────────────────────────────────
# Función 10: Hardening completo (todas las opciones)
# ──────────────────────────────────────────────
def full_hardening():
    """
    Ejecuta secuencialmente todas las medidas de hardening disponibles.
    Genera un reporte final con la fecha/hora de ejecución.
    Ideal para aplicar en una instalación nueva o recién desplegada.
    """
    print("\n  [*] Iniciando hardening completo del sistema...")
    inicio = datetime.datetime.now()
    logging.info("=== HARDENING COMPLETO INICIADO: %s ===", inicio)

    update_system()
    firewall()
    ssh_hardening()
    install_fail2ban()
    disable_services()
    permissions()

    fin = datetime.datetime.now()
    duracion = (fin - inicio).seconds
    logging.info(
        "=== HARDENING COMPLETO FINALIZADO: %s (duración: %ds) ===",
        fin,
        duracion,
    )

    print(f"""
  ╔══════════════════════════════════════════════╗
  ║       HARDENING COMPLETO FINALIZADO          ║
  ║  Inicio:   {inicio.strftime('%Y-%m-%d %H:%M:%S')}                ║
  ║  Fin:      {fin.strftime('%Y-%m-%d %H:%M:%S')}                ║
  ║  Duración: {duracion} segundos                        ║
  ║  Log guardado en: hexguard.log               ║
  ╚══════════════════════════════════════════════╝
""")


# ──────────────────────────────────────────────
# Menú interactivo principal
# ──────────────────────────────────────────────
def menu():
    """
    Muestra el menú principal y gestiona la selección del usuario.
    Valida la entrada para evitar opciones inválidas.
    """
    print("""
  ╔══════════════════════════════════════════════╗
  ║       HexGuard Security Toolkit              ║
  ╠══════════════════════════════════════════════╣
  ║  1.  Actualizar sistema                      ║
  ║  2.  Configurar firewall (UFW)               ║
  ║  3.  SSH hardening                           ║
  ║  4.  Instalar Fail2Ban                       ║
  ║  5.  Escaneo de rootkits                     ║
  ║  6.  Auditoría de usuarios                   ║
  ║  7.  Deshabilitar servicios inseguros        ║
  ║  8.  Verificar permisos críticos             ║
  ║  9.  Mostrar logs SSH                        ║
  ║  10. Hardening completo                      ║
  ╠══════════════════════════════════════════════╣
  ║  0.  Salir                                   ║
  ╚══════════════════════════════════════════════╝
""")

    opciones = {
        "1":  update_system,
        "2":  firewall,
        "3":  ssh_hardening,
        "4":  install_fail2ban,
        "5":  rootkit_scan,
        "6":  user_audit,
        "7":  disable_services,
        "8":  permissions,
        "9":  show_logs,
        "10": full_hardening,
    }

    try:
        opcion = input("  Selecciona una opción: ").strip()
    except KeyboardInterrupt:
        print("\n\n  [!] Interrupción detectada. Saliendo...\n")
        logging.info("Programa interrumpido por el usuario (Ctrl+C)")
        sys.exit(0)

    if opcion == "0":
        print("\n  [*] Saliendo de HexGuard. Stay secure.\n")
        logging.info("HexGuard cerrado por el usuario.")
        sys.exit(0)

    if opcion in opciones:
        logging.info("Opción seleccionada: %s", opcion)
        opciones[opcion]()
    else:
        print("  [!] Opción inválida. Por favor selecciona un número del 0 al 10.")


# ──────────────────────────────────────────────
# Parser de argumentos de línea de comandos
# ──────────────────────────────────────────────
def build_parser():
    """
    Construye y devuelve el parser de argumentos CLI con todas las flags
    disponibles, descripciones y ejemplos de uso.
    """
    parser = argparse.ArgumentParser(
        prog="hexguard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "  ██╗  ██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ \n"
            "  ██║  ██║██╔════╝╚██╗██╔╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗\n"
            "  ███████║█████╗   ╚███╔╝ ██║  ███╗██║   ██║███████║██████╔╝██║  ██║\n"
            "  ██╔══██║██╔══╝   ██╔██╗ ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║\n"
            "  ██║  ██║███████╗██╔╝ ██╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝\n"
            "  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝\n\n"
            "  HexGuard Security Hardening Toolkit — Advanced Linux Protection\n"
            "  Sin argumentos: lanza el menú interactivo.\n"
            "  Con flags:      ejecuta el módulo indicado y sale."
        ),
        epilog=(
            "ejemplos de uso:\n"
            "  sudo python3 hexguard.py                   # menú interactivo\n"
            "  sudo python3 hexguard.py --update          # MOD-01: actualizar sistema\n"
            "  sudo python3 hexguard.py --ssh --fail2ban  # MOD-03 + MOD-04 en secuencia\n"
            "  sudo python3 hexguard.py --full            # MOD-10: hardening completo\n"
            "  sudo python3 hexguard.py --logs --no-banner\n"
            "  sudo python3 hexguard.py --audit > reporte.txt\n"
        ),
    )

    # ── Módulos de hardening ────────────────────
    modulos = parser.add_argument_group("módulos de hardening")
    modulos.add_argument(
        "--update",
        action="store_true",
        help="MOD-01  Actualizar paquetes del sistema (apt update + upgrade)",
    )
    modulos.add_argument(
        "--firewall",
        action="store_true",
        help="MOD-02  Configurar UFW con política deny-all en entrante",
    )
    modulos.add_argument(
        "--ssh",
        action="store_true",
        help="MOD-03  Aplicar hardening en /etc/ssh/sshd_config",
    )
    modulos.add_argument(
        "--fail2ban",
        action="store_true",
        help="MOD-04  Instalar y activar Fail2Ban",
    )
    modulos.add_argument(
        "--scan",
        action="store_true",
        help="MOD-05  Ejecutar escaneo de rootkits con chkrootkit",
    )
    modulos.add_argument(
        "--audit",
        action="store_true",
        help="MOD-06  Auditoría de cuentas de usuario del sistema",
    )
    modulos.add_argument(
        "--services",
        action="store_true",
        help="MOD-07  Deshabilitar servicios inseguros (telnet, rsh, ftp...)",
    )
    modulos.add_argument(
        "--perms",
        action="store_true",
        help="MOD-08  Verificar y corregir permisos de archivos críticos",
    )
    modulos.add_argument(
        "--logs",
        action="store_true",
        help="MOD-09  Analizar intentos fallidos en auth.log",
    )
    modulos.add_argument(
        "--full",
        action="store_true",
        help="MOD-10  Ejecutar todos los módulos en secuencia",
    )

    # ── Opciones generales ──────────────────────
    general = parser.add_argument_group("opciones generales")
    general.add_argument(
        "--no-banner",
        action="store_true",
        dest="no_banner",
        help="Omitir el banner de inicio (útil en automatización/CI)",
    )
    general.add_argument(
        "--version",
        action="version",
        version="HexGuard 1.0.0 — by lucasfoking",
    )

    return parser


def run_flags(args):
    """
    Ejecuta los módulos correspondientes a las flags activas en el orden
    definido en la especificación. Devuelve True si se procesó al menos
    una flag, False si no había ninguna activa.

    Args:
        args (argparse.Namespace): Argumentos parseados por argparse.

    Returns:
        bool: True si se ejecutó al menos un módulo, False en caso contrario.
    """
    # Mapa ordenado: flag -> función
    modulos_activos = [
        (args.full,     full_hardening),   # --full tiene prioridad y ejecuta todo
        (args.update,   update_system),
        (args.firewall, firewall),
        (args.ssh,      ssh_hardening),
        (args.fail2ban, install_fail2ban),
        (args.scan,     rootkit_scan),
        (args.audit,    user_audit),
        (args.services, disable_services),
        (args.perms,    permissions),
        (args.logs,     show_logs),
    ]

    # Si --full está activo, ejecuta solo full_hardening y termina
    if args.full:
        full_hardening()
        return True

    ejecutado = False
    for activo, funcion in modulos_activos[1:]:   # Salta el entry de --full
        if activo:
            funcion()
            ejecutado = True

    return ejecutado


# ══════════════════════════════════════════════
# PUNTO DE ENTRADA PRINCIPAL
# ══════════════════════════════════════════════
if __name__ == "__main__":
    _parser = build_parser()
    _args = _parser.parse_args()

    # Mostrar banner salvo que se haya pasado --no-banner
    if not _args.no_banner:
        banner()

    check_root()
    logging.info("HexGuard iniciado")

    # Si se pasó alguna flag de módulo → modo no interactivo
    if run_flags(_args):
        sys.exit(0)

    # Sin flags → modo interactivo (menú en bucle)
    while True:
        menu()
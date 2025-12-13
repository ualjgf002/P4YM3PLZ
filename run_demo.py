"""run_demo.py

Pequeño script de automatización para arrancar ambos servidores (bueno y falso),
ejecutar clientes contra ellos y mostrar la salida. Diseñado para uso local
en modo demo educativo; NO ejecuta código malicioso.

Mejoras implementadas:
- Selección automática de puertos libres para evitar conflictos.
- Comentarios y manejo limpio de procesos.
- Logging a archivo run_demo.log
"""

import socket
import subprocess
import sys
import time
import os
import threading
import logging

# Configura logging a archivo Y consola
LOG_FILE = "run_demo.log"
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

PY = sys.executable


def get_free_port() -> int:
    """Obtiene un puerto libre en localhost devolviendo el número de puerto.

    Se abre un socket temporal, se liga al puerto 0 (ephemeral) y se cierra.
    """
    logger.debug("Buscando puerto libre...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    logger.debug(f"Puerto disponible encontrado: {port}")
    return port


def main():
    # Elegimos puertos libres para servidor bueno y falso
    port_good = get_free_port()
    port_fake = get_free_port()

    logger.info(f"Puertos elegidos -> bueno: {port_good}, falso: {port_fake}")

    # Lanzar los servidores en segundo plano, pasándoles el puerto como primer arg
    logger.info("Arrancando servidor bueno...")
    p_good = subprocess.Popen(
        [PY, "server_good_rsa.py", str(port_good)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    logger.info("Arrancando servidor falso...")
    p_fake = subprocess.Popen(
        [PY, "server_fake_rsa.py", str(port_fake)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    # Función para leer y volcar la salida de un proceso en tiempo real
    def stream_proc_output(proc, name):
        if not proc.stdout:
            logger.warning(f"No stdout para {name}")
            return
        for line in proc.stdout:
            logger.info(f"[{name}] {line.rstrip()}")

    # Arrancamos hilos que se encarguen de imprimir la salida de cada servidor
    t_good = threading.Thread(target=stream_proc_output, args=(p_good, "SERVER_GOOD"), daemon=True)
    t_fake = threading.Thread(target=stream_proc_output, args=(p_fake, "SERVER_FAKE"), daemon=True)
    t_good.start()
    t_fake.start()

    try:
        # Esperamos un poco para que los servidores queden a la escucha
        logger.info("Servidores arrancados, esperando 1s para estabilizar...")
        time.sleep(1)

        # Conectar cliente al servidor bueno (flujo normal)
        logger.info("== Conexión al servidor bueno ==")
        proc_client_good = subprocess.Popen(
            [PY, "-c", f"import client_rsa; client_rsa.conectar('127.0.0.1', {port_good}, 'www.bueno.com', 'bueno')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        # Imprimimos la salida del cliente
        out_good, _ = proc_client_good.communicate(timeout=20)
        logger.info("[CLIENT_GOOD] ----\n" + (out_good or "(sin salida)"))

        # Conectar cliente al servidor falso y aceptar la advertencia automáticamente
        logger.info("== Conexión al servidor falso (aceptando advertencia) ==")
        code = (
            "import builtins, client_rsa; builtins.input=lambda *a:'s'; "
            f"client_rsa.conectar('127.0.0.1', {port_fake}, 'www.banco-falso.com','falso')"
        )
        proc_client_fake = subprocess.Popen(
            [PY, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        out_fake, _ = proc_client_fake.communicate(timeout=20)
        logger.info("[CLIENT_FAKE] ----\n" + (out_fake or "(sin salida)"))

    except subprocess.TimeoutExpired:
        logger.error("Timeout: alguno de los procesos cliente no respondió a tiempo.")

    finally:
        # Cerramos los servidores de forma ordenada
        logger.info("Demo finalizada, cerrando servidores...")
        for p in (p_good, p_fake):
            try:
                p.terminate()
            except Exception:
                pass

        # Intentamos leer salidas restantes (no crítico)
        try:
            outg, _ = p_good.communicate(timeout=2)
            outf, _ = p_fake.communicate(timeout=2)
            if outg:
                logger.info("--- Servidor bueno (stdout restante) ---")
                logger.info(outg)
            if outf:
                logger.info("--- Servidor falso (stdout restante) ---")
                logger.info(outf)
        except Exception:
            pass

    logger.info(f"Log escrito en {LOG_FILE}. Abre ese archivo si no ves esta salida.")


if __name__ == "__main__":
    main()

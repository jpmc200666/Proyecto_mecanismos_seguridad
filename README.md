# Sistema de Detección y Mitigación Reactiva de Ataques DoS en Redes SDN mediante Machine Learning

Este proyecto implementa un sistema inteligente de seguridad perimetral para Redes Definidas por Software (SDN). Utiliza clasificadores basados en Inteligencia Artificial (**Random Forest**) para identificar y mitigar ataques de Denegación de Servicio (DoS) por inundación (**SYN, UDP e ICMP Flood**) en tiempo real, interactuando directamente con un conmutador OpenFlow administrado por el controlador Ryu dentro de un entorno emulado en Mininet. El desarrollo completo sigue el ciclo de vida del marco metodológico **CRISP-DM**.

## Tecnologías y Requisitos
* **Sistema Operativo:** Ubuntu 20.04 LTS
* **Entorno de Emulación:** Mininet
* **Conmutador SDN:** Open vSwitch
* **Controlador SDN:** Ryu Controller
* **Lenguaje de Programación:** Python 3
* **Librerías de IA:** Scikit-Learn, Pandas, NumPy, Joblib

## Guía de Instalación y Preparación

El proyecto incluye un script de automatización para preparar todas las dependencias del sistema operativo y los módulos de Python a nivel de sistema.

Para instalar todo el entorno de golpe, ejecuta los siguientes comandos en tu terminal de Ubuntu:

```bash
# 1. Dar permisos de ejecución al script de instalación
chmod +x setup.sh

# 2. Ejecutar la instalación automática de dependencias
sudo ./setup.sh
```

---

## Ciclo de Ejecución del Proyecto

El flujo de trabajo se divide en dos fases principales de acuerdo con la metodología CRISP-DM: la fase fuera de línea (recolección y entrenamiento) y la fase en línea (detección y mitigación en tiempo real).

### FASE 1: Recolección de Datos y Entrenamiento (Fuera de Línea)

1. **Generación y captura de tráfico de red:**
   Ejecuta la topología emulada para capturar tráfico legítimo y ráfagas de ataque controladas.
   ```bash
   sudo python3 collect_data.py --reps 10 --seed 1
   ```

2. **Construcción del conjunto de datos estructurado:**
   Procesa las capturas crudas (`.pcap`) convirtiéndolas en ventanas de tráfico temporales de 1 segundo para etiquetarlas.
   ```bash
   python3 build_dataset.py
   ```

3. **Entrenamiento de los modelos de Machine Learning:**
   Entrena y evalúa los clasificadores (Random Forest, Árbol de Decisión y SVM), guardando el mejor modelo predictivo en la carpeta `models/`.
   ```bash
   python3 train_models.py
   ```

### FASE 2: Demostración y Evaluación Estadística (En Línea)

4. **Automatización de pruebas de mitigación iterativas:**
   Para evaluar científicamente la robustez de la mitigación reactiva ante ataques en vivo, ejecuta el script de Bash que realiza 5 repeticiones consecutivas acumulando registros de rendimiento de red (RTT, pings y tasas de bloqueo):
   ```bash
   chmod +x ejecutar_pruebas.sh
   sudo ./ejecutar_pruebas.sh
   ```

5. **Consolidación estadística de resultados:**
   Una vez completadas las pruebas automatizadas, procesa las bitácoras generadas para calcular de forma matemática los promedios reales y construir las tablas definitivas de rendimiento de la red:
   ```bash
   python3 calcular_promedios.py
   ```

---

## Estructura del Repositorio

* `setup.sh`: Script Bash para la instalación de herramientas y librerías de sistema.
* `requirements.txt`: Archivo con las dependencias exactas de Python requeridas.
* `ejecutar_pruebas.sh`: Script Bash automatizado para correr el bucle de las 5 repeticiones de mitigación.
* `calcular_promedios.py`: Programa encargado de procesar los JSON locales para extraer promedios de RTT y pérdidas.
* `collect_data.py`, `build_dataset.py`, `train_models.py`: Pipeline principal de Machine Learning (CRISP-DM).
* `detector.py`, `run_demo.py`: Core del sistema IDS/IPS reactivo sobre la infraestructura SDN.
* `topology.py`, `traffic.py`, `common.py`: Scripts auxiliares de red, tráfico y topología de Mininet.
* `data/`: Directorio que contiene el entorno web de la víctima (`www/`) y las matrices de datos estructuradas (`dataset.csv`, `labels.csv`).
* `models/`: Carpeta destinada al almacenamiento del binario del clasificador inteligente entrenado.

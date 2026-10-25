# Mecanismos de Seguridad en Redes SDN mediante Machine Learning

Este repositorio contiene el código fuente para la emulación, detección y mitigación automatizada de ataques de denegación de servicio (DoS) en un entorno de redes definidas por software (SDN). El desarrollo sigue el ciclo de vida de la metodología CRISP-DM.

## Tecnologías y Requisitos
* **Entorno:** Ubuntu 20.04 LTS / Mininet
* **Controlador SDN:** Ryu Controller
* **Conmutador:** Open vSwitch (OpenFlow 1.3)
* **Lenguaje:** Python 3 (Scikit-Learn, Pandas, NumPy)

## Instrucciones de Ejecución

El proyecto se ejecuta de forma secuencial siguiendo estos pasos en la terminal:

1. **Generación y captura de tráfico (Fase fuera de línea):**
   ```bash
   sudo python3 collect_data.py --reps 10 --seed 1
   ```

2. **Construcción del conjunto de datos:**
   ```bash
   python3 build_dataset.py
   ```

3. **Entrenamiento de los modelos de Inteligencia Artificial:**
   ```bash
   python3 train_models.py
   ```

4. **Demostración y evaluación de la mitigación en vivo (Fase en línea):**
   Para probar un ataque individual de forma aislada:
   ```bash
   sudo python3 run_demo.py --attack syn_flood
   ```

5. **Automatización de múltiples repeticiones (Evaluación estadística):**
   Para ejecutar de forma iterativa el escenario completo en 5 repeticiones consecutivas con el fin de recolectar los registros de mitigación y pings necesarios para el análisis de varianza:
   ```bash
   sudo ./ejecutar_pruebas.sh
   ```

6. **Cálculo de métricas promedio y rendimiento de red:**
   Procesa los resultados consolidados de las 5 repeticiones generadas por el script de automatización para construir la tabla comparativa de rendimiento:
   ```bash
   python3 calcular_promedios.py
   ```


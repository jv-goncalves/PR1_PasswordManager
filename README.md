# 🔐 Password Manager - GUI

**Gestor seguro de contraseñas con interfaz gráfica | Python + Pyside6 + SQLite**  
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)](https://www.python.org)
[![PySide6](https://img.shields.io/badge/PySide6-6-41CD52?logo=qt&logoColor=white)](https://www.qt.io/qt-for-python)

---

## 🚀 Características Principales
- **Generación de contraseñas seguras** (longitud y caracteres personalizables).
- **Almacenamiento encriptado** usando AES-256.
- **Interfaz gráfica intuitiva** con Pyside6.
- Prevencion de acceso no autorizado mediante clave maestra.
- Base de datos local con SQLite.

---

## 📦 Instalación

### Requisitos
- Python 3.12+
- Git (opcional)

### Pasos
1. Clona el repositorio:
   ```bash
   git clone https://github.com/jv-goncalves/PR1_PasswordManager.git
   cd password-manager
2. Instala las dependencias:
   ```bash
     pip install -r requirements.txt
3. Ejecuta la aplicación:
   ```bash
     python Password_Manager.py

---

## 🖥 **Uso**  
### **Interfaz principal**  
![VentanaInicial](https://github.com/user-attachments/assets/6aa8e92e-556d-4fbe-8ba2-e96c3378bb7a)

1. **Generar contraseña**:  
   - Haz clic en *"Generar contraseña"* para crear una contraseña segura.  
   - Personaliza la longitud (8-32 caracteres) y tipos de caracteres (símbolos, números).  

2. **Guardar credenciales**:  
   - Completa los campos:  
     - **Servicio** **(Obligatorio)**: Nombre del servicio (ej: GitHub).  
     - **Usuario**: Nombre de usuario.  
     - **Mail**: Correo electrónico.
     - **Contraseña** **(Obligatorio)**: Generada automáticamente o ingresada manualmente.  
   - Haz clic en *"Guardar"* para almacenar de forma encriptada.  

3. **Visualizar servicios**:  
   - Haz click en "Contraseñas guardas.  
   - Click dereche en una fila para eliminar registros.  

---

<div align="center"> <sub>Creado con ❤️ por <a href="https://github.com/jv-goncalves">jv-goncalves</a></sub> </div>

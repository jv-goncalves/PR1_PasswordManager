from PySide6.QtWidgets import *
from PySide6 import QtUiTools
from PySide6.QtCore import Qt, QTimer
import secrets
import string
import sys
import json
import os
import bcrypt
import sqlite3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib


app = QApplication(sys.argv)
loader = QtUiTools.QUiLoader()

appPrincipal = loader.load(r"VentanaPrincipal.ui")
SetUpMasterPass=loader.load(r"DefinirContraMaestra.ui")
ventanaVerificacion=loader.load(r"InicioSesion.ui")





def calcular_hash(datos):
    datos_sin_hash = {k: v for k, v in datos.items() if k != "hash"}
    contenido = json.dumps(datos_sin_hash, ensure_ascii=False, indent=4)
    return hashlib.sha256(contenido.encode()).hexdigest()




deteccion_primerIni = r"IniApp.json"
def es_primer_inicio():
    if os.path.exists(deteccion_primerIni):
        try:
            with open(deteccion_primerIni, 'r', encoding='utf-8') as archivo:
                datos = json.load(archivo)

            if datos["contraseña"]=="":
                return True

            hash_guardado = datos.get("hash", "INICIO") 
            hash_calculado = calcular_hash(datos)

            if hash_guardado != hash_calculado:
                print("ADVERTENCIA: ¡El archivo ha sido modificado!")
            else:
                print("El archivo está verificado correctamente.")

            datos["hash"] = hash_calculado
            with open(deteccion_primerIni, 'w', encoding='utf-8') as archivo:
                json.dump(datos, archivo, ensure_ascii=False, indent=4)

            return False
        except Exception as e:
            print("❌ Error al leer el JSON:", e)
            return False

    else:
        print("⚠️ No existe el archivo, creando uno nuevo...")
        datos = {
            "contraseña": "", 
            "intentos_maximos": 10,
        }
        datos["hash"] = calcular_hash(datos)

        with open(deteccion_primerIni, 'w', encoding='utf-8') as archivo:
            json.dump(datos, archivo, ensure_ascii=False, indent=4)

        return True


informacion_verificacion=ventanaVerificacion.findChild(QLabel,"informacion_verificacion")
if es_primer_inicio():
    SetUpMasterPass.show()    
else:
    ventanaVerificacion.show()
    with open(deteccion_primerIni, "r", encoding='utf-8') as file:
            datos = json.load(file)
    informacion_verificacion.setText(f"Dispones de {datos["intentos_maximos"]} intentos antes de que los datos se eliminen.")   
    file.close()





campo_VerPass=ventanaVerificacion.findChild(QLineEdit, "campo_VerPass")
boton_comprobarVerPass=ventanaVerificacion.findChild(QPushButton, "boton_comprobarVerPass")


clave_aes=""
hash_guardado=""
def verificar_contraseña():
        with open(deteccion_primerIni, "r", encoding='utf-8') as file:
            datos = json.load(file)
            informacion_verificacion.setText(f"Dispones de {datos["intentos_maximos"]} intentos antes de que los datos se eliminen.")

            if "contraseña" in datos:
                hash_guardado = datos["contraseña"]
                if bcrypt.checkpw(campo_VerPass.text().encode('utf-8'), hash_guardado.encode('utf-8')):

                    if not os.path.exists("password_manager.db"):
                        crear_bd()
                    ejecutar_App()
                    ventanaVerificacion.close()
                else:
                    if datos["intentos_maximos"]==0:
                       try:
                           os.remove("password_manager.db")
                       except:
                            pass
                       file.close()
                       os.remove(deteccion_primerIni)
                       informacion_verificacion.setText(f"Datos borrados... debes volver a ejecutar el programa y definir una nueva contraseña maestra")
                       QTimer.singleShot(3000, lambda: QApplication.quit())
                       


                    else:
                        datos["intentos_maximos"] -=1
                        datos["hash"] = calcular_hash(datos)  # Actualizar el hash tras modificar intentos
            
                        with open(deteccion_primerIni, "w", encoding="utf-8") as file:
                            json.dump(datos, file, ensure_ascii=False, indent=4)

                        informacion_verificacion.setText(f"Dispones de {datos["intentos_maximos"]} intentos antes de que los datos se eliminen.")
            else:
                print("La clave 'contraseña' no existe en el archivo.")

boton_comprobarVerPass.clicked.connect(verificar_contraseña)

def generar_aes (clave_maestra):
    sal = b"16bytesdeSALT!!"  # Debe ser constante para poder descifrar luego
    kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=sal,
                iterations=100000
            )
    clave_aes = kdf.derive(clave_maestra.encode())
    return clave_aes
clave_aes=generar_aes(campo_VerPass.text())


def crear_bd():
    conn = sqlite3.connect("password_manager.db")  
    cursor = conn.cursor()

    cursor.execute("""
            CREATE TABLE IF NOT EXISTS contraseñas (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                SERVICIO TEXT NOT NULL,
                USUARIO TEXT,
                EMAIL TEXT,
                CONTRASEÑA TEXT NOT NULL
            )
            """)

    conn.commit()
    cursor.close()
    conn.close()


def borrar_tabla():
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS contraseñas")

    conn.commit()
    cursor.close()
    conn.close()


campo_IndicarPass=SetUpMasterPass.findChild(QLineEdit, "campo_IndicarPass")
campo_ConfirmarPass=SetUpMasterPass.findChild(QLineEdit, "campo_ConfirmarPass")
boton_confirmacionPass=SetUpMasterPass.findChild(QPushButton, "boton_confirmacionPass")
informacionUsuario=SetUpMasterPass.findChild(QLabel, "informacionUsuario")

def confirmar_contraseña():
    if campo_IndicarPass.text() == campo_ConfirmarPass.text():
        tiene_numeros = any(char.isdigit() for char in campo_ConfirmarPass.text())
        tiene_simbolos= any(not c.isalnum() for c in campo_ConfirmarPass.text())
        if tiene_numeros and tiene_simbolos and len(campo_ConfirmarPass.text())>=8:
            informacionUsuario.setText(f"Contraseña valida, el programa continuara en unos segundos...")
            
            hash_contraseña = bcrypt.hashpw(campo_ConfirmarPass.text().encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            with open(deteccion_primerIni, 'r', encoding='utf-8') as archivo:
                datos = json.load(archivo)
            datos["contraseña"]= hash_contraseña


            hash_calculado = calcular_hash(datos)
            datos["hash"] = hash_calculado

            with open(deteccion_primerIni, "w") as file:
                json.dump(datos, file, indent=4)
            
            if not os.path.exists("password_manager.db"):
                crear_bd()
            else:
                borrar_tabla()
                crear_bd()
            ejecutar_App()
            SetUpMasterPass.close()
        else:
            informacionUsuario.setText(f"La contraseña debe tener un numero, simbolos y al menos 8 caracteres...")
    else:
        informacionUsuario.setText(f"Atencion las contraseñas deben ser iguales para poder continuar...")
boton_confirmacionPass.clicked.connect(confirmar_contraseña)







def descifrar_contraseña(contraseña_cifrada, clave_aes):
    data = base64.b64decode(contraseña_cifrada)
  
    iv = data[:16]  
    contraseña_encrypted = data[16:]  

    cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv))
    decryptor = cipher.decryptor()

    contraseña_padded = decryptor.update(contraseña_encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    contraseña_descifrada = unpadder.update(contraseña_padded) + unpadder.finalize()

    return contraseña_descifrada.decode('utf-8')





def eliminar_fila_bd (id_servicio):
    conn = sqlite3.connect("password_manager.db")  
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM contraseñas WHERE ID = ?",
        (id_servicio,)
    )
    
    conn.commit()
    cursor.close()
    conn.close()

    actualizar_tabla_app()





def añadir_contraseña_bd (servicio, usuario, mail, passw):
    conn = sqlite3.connect("password_manager.db")  
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO contraseñas (SERVICIO, USUARIO, EMAIL, CONTRASEÑA) VALUES (?, ?, ?, ?)",
        (servicio, usuario, mail, passw)
    )
    
    conn.commit()
    cursor.close()
    conn.close()

    actualizar_tabla_app()

def actualizar_tabla_app():
    conn = sqlite3.connect("password_manager.db")  
    cursor = conn.cursor()

    tabla_pass = appPrincipal.findChild(QTableWidget, "tabla_pass")

    cursor.execute("SELECT * FROM contraseñas")
    resultados = cursor.fetchall()

    cant_column = tabla_pass.columnCount()

    tabla_pass.setRowCount(len(resultados))
    tabla_pass.clearContents()

    for x in range(0,len(resultados)):
            for y in range(0, cant_column):
                try:
                    if y==4:
                        contraseña_cifrada = str(resultados[x][y])
                        desencriptado = descifrar_contraseña(contraseña_cifrada, clave_aes)
                        objeto = QTableWidgetItem(desencriptado)
                        tabla_pass.setItem(x, y, objeto)

                    else:
                        objeto = QTableWidgetItem(str(resultados[x][y]))
                        tabla_pass.setItem(x,y, objeto)
                except Exception as err:
                    print(Exception, err)
    cursor.close()
    conn.close()


def show_context_menu(pos, table):
    global_pos = table.mapToGlobal(pos)
    index = table.indexAt(pos)
    if not index.isValid():
        return

    menu = QMenu()
    eliminar_fila = menu.addAction("Eliminar Fila")
    
    action = menu.exec(global_pos)
    if action == eliminar_fila:
        eliminar_fila_bd(int(index.siblingAtColumn(0).data()))
        table.removeRow(index.row())





def ejecutar_App():
    tabla_pass = appPrincipal.findChild(QTableWidget, "tabla_pass")
    tabla_pass.setEditTriggers(QTableWidget.NoEditTriggers)
    tabla_pass.setSortingEnabled(True)
    tabla_pass.setColumnHidden(0, True)
    
    actualizar_tabla_app()
    campo_servicio = appPrincipal.findChild(QLineEdit, "campo_AgregarServicio")
    campo_mail = appPrincipal.findChild(QLineEdit, "campo_AgregarMail")
    campo_usuario = appPrincipal.findChild(QLineEdit, "campo_AgregarUsuario")

    campo_AgregarContra = appPrincipal.findChild(QLineEdit, "campo_AgregarContra")




    boton_AgregarDatosUser = appPrincipal.findChild(QPushButton, "boton_AgregarDatosUser")
    boton_GenerarPass = appPrincipal.findChild(QPushButton, "boton_GenerarPass")
    boton_copiarContraGen = appPrincipal.findChild(QPushButton, "boton_copiarContraGen")


    indicador_slider_PassGen=appPrincipal.findChild(QLabel, "slider_Addon_MostrarLongContraSeleccionada")



    slider_longPassGen=appPrincipal.findChild(QSlider, "longitud_contra_gen")
    def actualizar_indicador(valor):
        indicador_slider_PassGen.setText(f"{valor}")
    slider_longPassGen.valueChanged.connect(actualizar_indicador)



    check_MostrarContraGen=appPrincipal.findChild(QCheckBox, "check_MostrarContraGen")
    campo_contraGen = appPrincipal.findChild(QLineEdit, "campo_contraGen")
    def mostrarContraGen():
        if check_MostrarContraGen.checkState() == Qt.Checked:
            campo_contraGen.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            campo_contraGen.setEchoMode(QLineEdit.EchoMode.Password)
    check_MostrarContraGen.checkStateChanged.connect(mostrarContraGen)



    check_Agregar_MostrarContra=appPrincipal.findChild(QCheckBox, "check_Agregar_MostrarContra")
    def mostrarContraAgregar():
        if check_Agregar_MostrarContra.checkState() == Qt.Checked:
            campo_AgregarContra.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            campo_AgregarContra.setEchoMode(QLineEdit.EchoMode.Password)
    check_Agregar_MostrarContra.checkStateChanged.connect(mostrarContraAgregar)



    def cifrar_contraseña(contraseña, clave_aes):
        if isinstance(clave_aes, str):
            clave_aes = clave_aes.encode()

        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        contraseña_padded = padder.update(contraseña.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv))
        encryptor = cipher.encryptor()

        contraseña_cifrada = encryptor.update(contraseña_padded) + encryptor.finalize()

        return base64.b64encode(iv + contraseña_cifrada).decode()



    texto_agregarDatosInformacion=appPrincipal.findChild(QLabel,"texto_agregarDatosInformacion")
    def guardar_contraseña():
        if campo_servicio.text() =="" or campo_AgregarContra.text() =="":
            texto_agregarDatosInformacion.setText("Los datos de servicio y contraseña son obligatorios...")
        else:
            texto_agregarDatosInformacion.setText("Contraseña guardada correctamente...")
            contraseña_cifrada=cifrar_contraseña(campo_AgregarContra.text(), clave_aes)
            añadir_contraseña_bd(campo_servicio.text(),campo_usuario.text(),campo_mail.text(),contraseña_cifrada)
    boton_AgregarDatosUser.clicked.connect(guardar_contraseña)

    


    check_Generar_IncluirSimbolos=appPrincipal.findChild(QCheckBox, "check_Generar_IncluirSimbolos")
    check_Generar_IncluirNumeros=appPrincipal.findChild(QCheckBox, "check_Generar_IncluirNumeros")
    check_Generar_IncluirMayus=appPrincipal.findChild(QCheckBox, "check_Generar_IncluirMayus")
    def generar_Contraseña():
        longitud = slider_longPassGen.value()
        caracteres = string.ascii_lowercase
        if check_Generar_IncluirSimbolos.checkState() == Qt.Checked:
            caracteres=caracteres+"!@#$%^&*"
        if check_Generar_IncluirNumeros.checkState() == Qt.Checked:
            caracteres=caracteres+string.digits
        if check_Generar_IncluirMayus.checkState() == Qt.Checked:
            caracteres=caracteres+string.ascii_uppercase
        contraseña = ''.join(secrets.choice(caracteres) for _ in range(longitud))
        campo_contraGen.setText(contraseña)
        print("Contraseña generada!")
    boton_GenerarPass.clicked.connect(generar_Contraseña)

    def copiar_contraseña():
        app.clipboard().setText(campo_contraGen.text())
        print("Contraseña copiada!")
    boton_copiarContraGen.clicked.connect(copiar_contraseña)


    tabla_pass.setContextMenuPolicy(Qt.CustomContextMenu)
    tabla_pass.customContextMenuRequested.connect(lambda pos: show_context_menu(pos, tabla_pass))
    

    appPrincipal.show()
app.exec()
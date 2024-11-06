import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
import threading

API_URL = "http://127.0.0.1:8000/check_query/"

def check_sql_query():
    query = entry.get("1.0", "end-1c")
    
    def make_request():
        try:
            response = requests.post(API_URL, json={"query": query})
            print(f"Response status code: {response.status_code}")
            print(f"Response content: {response.text}")

            if response.status_code == 200:
                data = response.json()
                show_result_window(data) 
            else:
                error_data = response.json()
                # Si la respuesta tiene un objeto 'detail', extraer sus valores para mostrarlos
                if "detail" in error_data:
                    show_error_window(error_data["detail"])
                else:
                    show_error_window({"message": "Error desconocido", "acción": "Limitar acceso", "grado_de_severidad": "Desconocido", "patrón_detectado": "Ninguno", "query_analizada": "No disponible"}) 
        
        except requests.exceptions.RequestException as e:
            print(f"Request Exception: {e}")
            show_error_window({"detail": {"message": "No se pudo conectar con la API."}})  # Mostrar error de conexión
    
    threading.Thread(target=make_request, daemon=True).start()

def show_result_window(data):
    result_window = tk.Toplevel(root)
    result_window.title("Resultado del Análisis de Inyección SQL")
    result_window.geometry("500x400")
    result_window.configure(bg="#1e1e1e")

    title_label = tk.Label(result_window, text="Resultado del Análisis de Inyección SQL", font=("Helvetica", 16, "bold"), fg="#FFD700", bg="#1e1e1e")
    title_label.pack(pady=10)

    message_label = tk.Label(result_window, text="Mensaje:", font=("Helvetica", 12, "bold"), fg="#ffffff", bg="#1e1e1e")
    message_label.pack(anchor="w", padx=20)
    message_content = tk.Label(result_window, text=data.get("message", "Consulta segura."), font=("Helvetica", 11), fg="#b0e57c", bg="#1e1e1e")
    message_content.pack(anchor="w", padx=40, pady=5)

    action_label = tk.Label(result_window, text="Acción Sugerida:", font=("Helvetica", 12, "bold"), fg="#ffffff", bg="#1e1e1e")
    action_label.pack(anchor="w", padx=20)
    action_content = tk.Label(result_window, text=data.get("acción", "No hay acción especificada."), font=("Helvetica", 11), fg="#ffa07a", bg="#1e1e1e")
    action_content.pack(anchor="w", padx=40, pady=5)

    severity_label = tk.Label(result_window, text="Grado de Severidad:", font=("Helvetica", 12, "bold"), fg="#ffffff", bg="#1e1e1e")
    severity_label.pack(anchor="w", padx=20)
    severity_content = tk.Label(result_window, text=data.get("grado_de_severidad", "Desconocido").capitalize(), font=("Helvetica", 11), fg="#ff6347", bg="#1e1e1e")
    severity_content.pack(anchor="w", padx=40, pady=5)

    pattern_label = tk.Label(result_window, text="Patrón Detectado:", font=("Helvetica", 12, "bold"), fg="#ffffff", bg="#1e1e1e")
    pattern_label.pack(anchor="w", padx=20)
    pattern_content = tk.Label(result_window, text=data.get("patrón_detectado", "No se detectaron patrones específicos."), font=("Helvetica", 11), fg="#87cefa", bg="#1e1e1e")
    pattern_content.pack(anchor="w", padx=40, pady=5)

    query_label = tk.Label(result_window, text="Consulta Analizada:", font=("Helvetica", 12, "bold"), fg="#ffffff", bg="#1e1e1e")
    query_label.pack(anchor="w", padx=20)
    query_content = tk.Label(result_window, text=data.get("query_analizada", "Consulta no disponible."), font=("Courier", 10), fg="#dcdcdc", bg="#1e1e1e")
    query_content.pack(anchor="w", padx=40, pady=5)

    close_button = tk.Button(result_window, text="Cerrar", command=result_window.destroy, font=("Helvetica", 10, "bold"), bg="#ff4d4d", fg="#ffffff")
    close_button.pack(pady=15)

def show_error_window(error_data):
    error_window = tk.Toplevel(root)
    error_window.title("Error de Seguridad")
    error_window.geometry("500x400")
    error_window.configure(bg="#2c2c2c")

    title_label = tk.Label(error_window, text="¡Error Detectado!", font=("Helvetica", 16, "bold"), fg="#ff6347", bg="#2c2c2c")
    title_label.pack(pady=10)

    message_label = tk.Label(error_window, text="Mensaje:", font=("Helvetica", 12, "bold"), fg="#ffffff", bg="#2c2c2c")
    message_label.pack(anchor="w", padx=20)
    # Extraemos y mostramos el mensaje del objeto detail
    message_content = tk.Label(error_window, text=error_data.get("message", "Consulta rechazada debido a inyección SQL."), font=("Helvetica", 11), fg="#ffcc00", bg="#2c2c2c")
    message_content.pack(anchor="w", padx=40, pady=5)

    action_label = tk.Label(error_window, text="Acción Sugerida:", font=("Helvetica", 12, "bold"), fg="#ffffff", bg="#2c2c2c")
    action_label.pack(anchor="w", padx=20)
    # Extraemos y mostramos la acción sugerida
    action_content = tk.Label(error_window, text=error_data.get("acción", "Limitar acceso."), font=("Helvetica", 11), fg="#ffa07a", bg="#2c2c2c")
    action_content.pack(anchor="w", padx=40, pady=5)

    severity_label = tk.Label(error_window, text="Grado de Severidad:", font=("Helvetica", 12, "bold"), fg="#ffffff", bg="#2c2c2c")
    severity_label.pack(anchor="w", padx=20)
    # Extraemos y mostramos el grado de severidad
    severity_content = tk.Label(error_window, text=error_data.get("grado_de_severidad", "Moderado").capitalize(), font=("Helvetica", 11), fg="#ff6347", bg="#2c2c2c")
    severity_content.pack(anchor="w", padx=40, pady=5)

    pattern_label = tk.Label(error_window, text="Patrón Detectado:", font=("Helvetica", 12, "bold"), fg="#ffffff", bg="#2c2c2c")
    pattern_label.pack(anchor="w", padx=20)
    # Extraemos y mostramos el patrón detectado
    pattern_content = tk.Label(error_window, text=error_data.get("patrón_detectado", "'1'='1'"), font=("Helvetica", 11), fg="#87cefa", bg="#2c2c2c")
    pattern_content.pack(anchor="w", padx=40, pady=5)

    query_label = tk.Label(error_window, text="Consulta Analizada:", font=("Helvetica", 12, "bold"), fg="#ffffff", bg="#2c2c2c")
    query_label.pack(anchor="w", padx=20)
    # Extraemos y mostramos la consulta analizada
    query_content = tk.Label(error_window, text=error_data.get("query_analizada", "Consulta no disponible."), font=("Courier", 10), fg="#dcdcdc", bg="#2c2c2c")
    query_content.pack(anchor="w", padx=40, pady=5)

    close_button = tk.Button(error_window, text="Cerrar", command=error_window.destroy, font=("Helvetica", 10, "bold"), bg="#ff4d4d", fg="#ffffff")
    close_button.pack(pady=15)

root = tk.Tk()
root.title("Verificación de Inyección SQL")
root.geometry("450x350")
root.configure(bg="#2d2d2d") 

title_label = tk.Label(root, text="Verificación de Inyección SQL", font=("Helvetica", 16, "bold"), fg="#ffffff", bg="#2d2d2d")
title_label.pack(pady=10)

label = tk.Label(root, text="Ingrese la consulta SQL:", font=("Helvetica", 12), fg="#ffffff", bg="#2d2d2d")
label.pack(pady=5)

entry = scrolledtext.ScrolledText(root, height=5, width=45, font=("Courier", 10))
entry.pack(pady=5)

check_button = tk.Button(root, text="Verificar Consulta", font=("Helvetica", 12, "bold"), bg="#4CAF50", fg="#ffffff", command=check_sql_query)
check_button.pack(pady=15)

footer_label = tk.Label(root, text="La consulta será verificada contra patrones de inyección SQL conocidos.", font=("Helvetica", 10), fg="#ffffff", bg="#2d2d2d")
footer_label.pack(pady=10)

root.mainloop()

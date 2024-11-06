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
            print(response)
            print(f"Response status code: {response.status_code}")
            print(f"Response content: {response.text}")

            if response.status_code == 200:
                data = response.json()
                messagebox.showinfo("Resultado", data.get("message", "Consulta segura."))
            else:
                error_data = response.json()
                messagebox.showerror("Error de Seguridad", error_data.get("detail", "Se detectó inyección SQL."))
        
        except requests.exceptions.RequestException as e:
            print(f"Request Exception: {e}")
            messagebox.showerror("Error de Conexión", "No se pudo conectar con la API.")
    
    threading.Thread(target=make_request, daemon=True).start()

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

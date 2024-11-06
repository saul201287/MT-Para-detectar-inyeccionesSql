import queue
import threading

class SQLInjectionTuringMachine:
    def __init__(self):
        self.state = 'q0'
        self.head_position = 0
        self.injection_detected = False
        self.injection_severity = "baja"
        self.result_queue = queue.Queue()
        self.current_pattern = ""
        
    def reset(self, query):
        self.state = 'q0'
        self.head_position = 0
        self.injection_detected = False
        self.injection_severity = "baja"
        self.tape = list(query.lower())
        self.current_pattern = ""
        
    def move_right(self):
        self.head_position += 1
        
    def read_symbol(self):
        return self.tape[self.head_position] if self.head_position < len(self.tape) else None

    def detect_injection_patterns(self):
        full_query = ''.join(self.tape).lower()
        
        # Primero detectamos patrones de alta severidad
        high_severity_patterns = [
            "union select",
            "select count",
            "(select",
            "union",
            "or (select",
            ") >",
            "or select",
            "having",
            "group by"
        ]
        
        # Patrones de severidad media
        medium_severity_patterns = [
            "or 'a'='a'",
            "and password",
            "'1'='1'",
            "or 1=1",
            "or true",
            "or 'true'",
            " or ",
            "'=''"
        ]
        
        # Patrones de severidad baja
        low_severity_patterns = [
            "--",
            "''",
            "' or '1",
            "#",
            "/*",
            "*/"
        ]

        # Verificar patrones de alta severidad
        for pattern in high_severity_patterns:
            if pattern in full_query:
                self.injection_detected = True
                self.injection_severity = "alta"
                self.current_pattern = pattern
                return True

        # Verificar patrones de severidad media
        for pattern in medium_severity_patterns:
            if pattern in full_query:
                self.injection_detected = True
                self.injection_severity = "media"
                self.current_pattern = pattern
                return True

        # Verificar patrones de severidad baja
        for pattern in low_severity_patterns:
            if pattern in full_query:
                self.injection_detected = True
                self.injection_severity = "baja"
                self.current_pattern = pattern
                return True

        # Análisis adicional para patrones especiales
        quote_count = full_query.count("'")
        paren_count = full_query.count("(")
        
        if quote_count > 2:  # Más de dos comillas simples podría indicar inyección
            self.injection_detected = True
            self.injection_severity = "baja"
            self.current_pattern = "multiple quotes"
            return True
            
        if paren_count > 1:  # Múltiples paréntesis podrían indicar subconsultas
            self.injection_detected = True
            self.injection_severity = "alta"
            self.current_pattern = "nested queries"
            return True

        return False

    def handle_detection(self):
        if not self.injection_detected:
            return {
                "message": "La consulta es segura.",
                "query_analizada": ''.join(self.tape)
            }

        if self.injection_severity == "baja":
            return {
                "message": "Consulta rechazada debido a un patrón simple de inyección SQL.",
                "acción": "rechazar_consulta",
                "grado_de_severidad": self.injection_severity,
                "patrón_detectado": self.current_pattern,
                "query_analizada": ''.join(self.tape)
            }

        elif self.injection_severity == "media":
            return {
                "message": "Consulta rechazada y acceso limitado debido a un intento moderado de inyección SQL.",
                "acción": "limitar_acceso",
                "grado_de_severidad": self.injection_severity,
                "patrón_detectado": self.current_pattern,
                "query_analizada": ''.join(self.tape)
            }

        elif self.injection_severity == "alta":
            return {
                "message": "Consulta rechazada y administrador notificado debido a un intento de inyección SQL de alta severidad.",
                "acción": "notificar_administrador",
                "grado_de_severidad": self.injection_severity,
                "patrón_detectado": self.current_pattern,
                "details": "Patrón complejo detectado (por ejemplo, subconsultas, UNION, lógica avanzada).",
                "query_analizada": ''.join(self.tape)
            }

    def _run_detection_thread(self, query):
        self.reset(query)
        injection_detected = self.detect_injection_patterns()
        self.result_queue.put(injection_detected)

    def is_malicious(self, query):
        print(f"\nAnalizando query: {query}")
        detection_thread = threading.Thread(target=self._run_detection_thread, args=(query,))
        detection_thread.start()
        detection_thread.join()
        injection_detected = self.result_queue.get()
        return self.handle_detection() if injection_detected else {"message": "La consulta es segura."}
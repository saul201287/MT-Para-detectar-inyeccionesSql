import queue
import threading


class SQLInjectionTuringMachine:
    def __init__(self):
        self.state = 'q0'
        self.head_position = 0
        self.injection_detected = False
        self.injection_severity = "baja"
        self.result_queue = queue.Queue()

    def reset(self, query):
        self.state = 'q0'
        self.head_position = 0
        self.injection_detected = False
        self.injection_severity = "baja"
        self.tape = list(query)

    def move_right(self):
        self.head_position += 1

    def read_symbol(self):
        return self.tape[self.head_position] if self.head_position < len(self.tape) else None

    def detect_injection_patterns(self):
        while self.state != 'halt':
            symbol = self.read_symbol()
            if symbol is None:
                break

            if self.state == 'q0':
                if symbol in ["'", '"']:
                    self.state = 'q1'
                elif symbol == '-':
                    self.state = 'q2'
                elif symbol == 'O':
                    self.state = 'q6'  # Para detectar OR
                elif symbol == 'A':
                    self.state = 'q4'
                elif symbol == '(':
                    self.state = 'q5'
                else:
                    self.move_right()

            elif self.state == 'q1':  # Después de encontrar comillas
                if symbol == ' ' or symbol == 'O':
                    self.state = 'q3'
                else:
                    self.state = 'q0'
                self.move_right()

            elif self.state == 'q2':  
                if symbol == '-':
                    self.injection_detected = True
                    self.injection_severity = "baja"
                    self.state = 'halt'
                else:
                    self.state = 'q0'
                self.move_right()

            elif self.state == 'q3': 
                if symbol == 'R':
                    self.state = 'q7' 
                else:
                    self.state = 'q0'
                self.move_right()

            elif self.state == 'q4':
                if symbol == 'N':
                    self.injection_detected = True
                    self.injection_severity = "media"
                    self.state = 'halt'
                else:
                    self.state = 'q0'
                self.move_right()

            elif self.state == 'q5':
                if symbol == 'S':
                    self.injection_detected = True
                    self.injection_severity = "alta"
                    self.state = 'halt'
                else:
                    self.state = 'q0'
                self.move_right()

            elif self.state == 'q6':  
                if symbol == ' ' or symbol == '=':
                    self.state = 'q7'
                else:
                    self.state = 'q0'
                self.move_right()

            elif self.state == 'q7':  
                if symbol == '=':
                    self.state = 'q8'  
                else:
                    self.state = 'q0'
                self.move_right()

            elif self.state == 'q8':  
                if symbol == "'":
                    self.injection_detected = True
                    self.injection_severity = "media"
                    self.state = 'halt'
                else:
                    self.state = 'q0'
                self.move_right()

        return self.injection_detected

    def handle_detection(self):
        """
        Define acciones basadas en la severidad de la inyección SQL detectada.
        """
        if not self.injection_detected:
            return {"message": "La consulta es segura."}

        if self.injection_severity == "baja":
            return {
                "message": "Consulta rechazada debido a un patrón simple de inyección SQL.",
                "action": "rechazar_consulta",
                "severity": self.injection_severity
            }

        elif self.injection_severity == "media":
            return {
                "message": "Consulta rechazada y acceso limitado debido a un intento moderado de inyección SQL.",
                "action": "limitar_acceso",
                "severity": self.injection_severity
            }

        elif self.injection_severity == "alta":
            return {
                "message": "Consulta rechazada y administrador notificado debido a un intento de inyección SQL de alta severidad.",
                "action": "notificar_administrador",
                "severity": self.injection_severity,
                "details": "Patrón complejo detectado (por ejemplo, subconsultas, lógica avanzada)."
            }

    def _run_detection_thread(self, query):
        """Función que se ejecutará en un hilo separado."""
        self.reset(query)
        injection_detected = self.detect_injection_patterns()
        self.result_queue.put(injection_detected)

    def is_malicious(self, query):
        print(query)
        detection_thread = threading.Thread(target=self._run_detection_thread, args=(query,))
        detection_thread.start()
        detection_thread.join()
        injection_detected = self.result_queue.get()
        print(injection_detected)
        return self.handle_detection() if injection_detected else {"message": "La consulta es segura."}

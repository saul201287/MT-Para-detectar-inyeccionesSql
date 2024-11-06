import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from maquina_turing import SQLInjectionTuringMachine

# Instancia de la máquina de Turing para detección de inyección SQL
turing_machine = SQLInjectionTuringMachine()

app = FastAPI()

# Configuración de logger
logger = logging.getLogger(__name__)

# Modelo para la entrada de la consulta SQL
class QueryRequest(BaseModel):
    query: str

# Middleware para validar la consulta SQL
@app.middleware("http")
async def sql_injection_middleware(request: Request, call_next):
    try:
        # Obtención del cuerpo de la solicitud
        body = await request.json()
        query = body.get("query", "")
        
        # Verificación de inyección SQL utilizando la máquina de Turing
        is_malicious = turing_machine.is_malicious(query)
        print(is_malicious)

        # Validación del resultado obtenido
        if is_malicious.get('message') != "La consulta es segura.":
            raise HTTPException(status_code=400, detail="Inyección SQL maliciosa detectada en la query")
        else:
            return JSONResponse(content={"message": "Query segura"}, status_code=200)
        
        # Continuar con el siguiente paso del middleware
        response = await call_next(request)
        return response

    except HTTPException as e:
        # Manejo de excepciones HTTP
        if e.status_code == 400:
            return JSONResponse(content={"detail": e.detail}, status_code=400)
        return JSONResponse(content={"detail": "Internal server error"}, status_code=500)

# Ruta para comprobar la consulta
@app.post("/check_query")
async def check_query(query: QueryRequest):
    return {"message": "Query processed successfully", "query": query.query}

# Ejecutar la aplicación
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

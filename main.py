import time
import asyncio
import pandas as pd
import io
import os
import google.generativeai as genai
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)
from datetime import datetime, timedelta
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

# Configuración desde archivo externo
from keys.keys import TELEGRAM_TOKEN, GEMINI_API_KEY

# Configuración de seguridad
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_USER_REQUESTS = 5  # Máximo de solicitudes concurrentes por usuario
DATA_CACHE_TTL = 30 * 60  # 30 minutos en segundos
MAX_CACHED_USERS = 100  # Máximo de usuarios en caché

# Configurar Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel(model_name="gemini-1.5-flash")

# Almacenamiento de datos con expiración y límite
user_data = OrderedDict()
executor = ThreadPoolExecutor(max_workers=4)

class CSVSecurity:
    @staticmethod
    def is_valid_csv(content):
        """Verifica si el contenido es un CSV válido"""
        try:
            with io.BytesIO(content) as file_stream:
                pd.read_csv(file_stream, nrows=1)
                return True
        except:
            return False

    @staticmethod
    def is_potentially_malicious(df):
        """Detecta contenido potencialmente malicioso en el DataFrame"""
        suspicious_prefixes = ('=', '+', '-', '@', 'http://', 'https://')
        for col in df.columns:
            if df[col].astype(str).str.startswith(suspicious_prefixes).any():
                return True
        return False

    @staticmethod
    def sanitize_data(df):
        """Sanitiza el DataFrame escapando fórmulas y URLs"""
        return df.applymap(lambda x: f"'{x}" if isinstance(x, str) and x.startswith(
            ('=', '+', '-', '@', 'http://', 'https://')
        ) else x)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Maneja el comando /start"""
    await update.message.reply_text(
        "👋 ¡Hola! Envíame un archivo *CSV* para analizar:\n\n"
        "📊 CSV - Para datos tabulares\n"
        "(Solo archivos CSV válidos, máximo 100MB)\n\n"
        "⚠️ Por seguridad, los archivos se borran después de 30 minutos"
    )

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Procesa el archivo CSV enviado por el usuario"""
    # Verificar límite de solicitudes
    if sum(1 for uid in user_data if uid == update.message.chat_id) >= MAX_USER_REQUESTS:
        await update.message.reply_text("⚠️ Has alcanzado el límite de solicitudes concurrentes.")
        return

    file = await update.message.document.get_file()
    file_name = update.message.document.file_name

    if not file_name.lower().endswith('.csv'):
        await update.message.reply_text("⚠️ Solo se aceptan archivos con extensión .csv válida.")
        return

    if file.file_size > MAX_FILE_SIZE:
        await update.message.reply_text(
            f"⚠️ Archivo demasiado grande ({(file.file_size/1024/1024):.1f}MB). Máximo permitido: 100MB"
        )
        return

    msg = await update.message.reply_text("📥 Descargando y verificando archivo CSV...")

    try:
        content = await file.download_as_bytearray()

        # Verificar que es un CSV válido
        if not CSVSecurity.is_valid_csv(content):
            await msg.edit_text("❌ El archivo no es un CSV válido.")
            return

        # Procesar en un hilo separado para no bloquear el event loop
        df, row_count = await asyncio.get_event_loop().run_in_executor(
            executor, process_csv_data, content
        )

        # Sanitizar datos
        if CSVSecurity.is_potentially_malicious(df):
            await msg.edit_text("⚠️ Se detectaron posibles fórmulas/URLs maliciosas. Sanitizando datos...")
            df = CSVSecurity.sanitize_data(df)

        # Almacenar datos con timestamp
        user_data[update.message.chat_id] = {
            'data': df,
            'timestamp': datetime.now(),
            'row_count': row_count,
            'columns': df.columns.tolist()
        }
        
        # Mantener sólo los últimos MAX_CACHED_USERS
        if len(user_data) > MAX_CACHED_USERS:
            user_data.popitem(last=False)

        await send_file_analysis_response(update, msg, row_count, df.columns)

    except Exception as e:
        await msg.edit_text("❌ Error al procesar el archivo. Por favor, verifica que sea un CSV válido.")
        print(f"Error processing file: {e}")

def process_csv_data(content):
    """Procesa el CSV en un hilo separado"""
    with io.BytesIO(content) as file_stream:
        # Primera pasada para contar filas
        row_count = sum(1 for _ in file_stream) - 1
        file_stream.seek(0)
        
        # Leer muestras según tamaño
        if row_count <= 10000:
            df = pd.read_csv(file_stream, encoding='utf-8', on_bad_lines='warn')
        else:
            sample_size = min(10000, max(1000, int(row_count * 0.01)))
            df = pd.read_csv(file_stream, nrows=sample_size, encoding='utf-8', on_bad_lines='warn')
        
        return df, row_count

async def send_file_analysis_response(update, msg, row_count, columns):
    """Envía el resumen del análisis del CSV al usuario"""
    processing_time = time.time() - msg.date.timestamp()
    response = (
        f"✅ CSV analizado ({row_count:,} filas)\n"
        f"⏱ Tiempo: {processing_time:.1f}s\n\n"
        f"🔡 Columnas ({len(columns)}):\n{', '.join(columns[:5])}"
    )
    if len(columns) > 5:
        response += f" + {len(columns)-5} más...\n\n"
    response += (
        f"\n💡 Puedes preguntar por:\n"
        f"- Análisis de columnas específicas\n"
        f"- Estadísticas de los datos\n"
        f"- Patrones o tendencias\n\n"
        f"⚠️ Los datos se borrarán en 30 minutos"
    )
    await msg.edit_text(response)

async def handle_question(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Maneja las preguntas del usuario sobre los datos"""
    chat_id = update.message.chat_id
    
    # Verificar datos existentes y expiración
    if chat_id not in user_data or (
        datetime.now() - user_data[chat_id]['timestamp'] > timedelta(seconds=DATA_CACHE_TTL)
    ):
        await update.message.reply_text("⚠️ No hay datos activos. Envía un nuevo archivo CSV.")
        if chat_id in user_data:
            user_data.pop(chat_id)
        return

    data_info = user_data[chat_id]
    question = update.message.text.strip()
    df = data_info['data']

    # Respuesta rápida para consultas de columnas
    if question.lower() in map(str.lower, data_info['columns']):
        col = next(c for c in data_info['columns'] if c.lower() == question.lower())
        await answer_column_question(update, df, col)
        return

    # Consultas complejas a Gemini
    await handle_gemini_question(update, data_info, question, df)

async def answer_column_question(update, df, col):
    """Responde preguntas específicas sobre columnas"""
    sample = df[col].dropna().sample(min(5, len(df))).tolist()
    response = (
        f"📊 Columna: {col}\n"
        f"- Tipo: {df[col].dtype}\n"
        f"- Valores únicos: {df[col].nunique():,}\n"
        f"- Nulos: {df[col].isna().sum():,} ({df[col].isna().mean()*100:.1f}%)\n"
        f"- Ejemplos:\n"
    ) + "\n".join(f"  • {str(x)}" for x in sample)
    await update.message.reply_text(response)

async def handle_gemini_question(update, data_info, question, df):
    """Procesa preguntas complejas usando Gemini"""
    msg = await update.message.reply_text("🔍 Procesando tu consulta...")

    try:
        # Preparar datos para Gemini
        data_str = (
            f"Muestra de {len(df):,} filas (de {data_info['row_count']:,})\n"
            f"Columnas: {', '.join(data_info['columns'])}\n\n"
            f"Primeras filas:\n{df.head().to_csv(index=False)}\n\n"
            f"Estadísticas:\n{df.describe().to_csv()}"
        )

        prompt = (
            f"Analiza estos datos CSV según la pregunta del usuario.\n\n"
            f"Datos:\n{data_str}\n\n"
            f"Pregunta: {question}\n\n"
            f"Instrucciones:\n"
            f"- Responde en español de forma clara y concisa\n"
            f"- Incluye análisis cuantitativo cuando sea relevante\n"
            f"- Destaca patrones o anomalías importantes\n"
            f"- Limita la respuesta a 1000 palabras"
        )

        # Ejecutar Gemini en un hilo separado
        response = await asyncio.get_event_loop().run_in_executor(
            executor, model.generate_content, prompt
        )
        
        await msg.edit_text(response.text)

    except Exception as e:
        await msg.edit_text("⚠️ Error al procesar tu consulta. Intenta reformularla.")
        print(f"Gemini error: {e}")

def cleanup_user_data():
    """Limpiar datos expirados"""
    now = datetime.now()
    expired_users = [
        uid for uid, data in user_data.items()
        if now - data['timestamp'] > timedelta(seconds=DATA_CACHE_TTL)
    ]
    for uid in expired_users:
        user_data.pop(uid, None)

async def periodic_cleanup():
    """Limpieza periódica sin usar JobQueue"""
    while True:
        cleanup_user_data()
        await asyncio.sleep(3600)  # Espera 1 hora

if __name__ == "__main__":
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    
    # Handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.FileExtension("csv"), handle_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_question))
    
    # Iniciar tarea de limpieza en segundo plano
    loop = asyncio.get_event_loop()
    loop.create_task(periodic_cleanup())
    
    print("🤖 Bot seguro para análisis de CSV funcionando...")
    app.run_polling()
